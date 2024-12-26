package devguard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/gosimple/slug"
	"github.com/l3montree-dev/devguard/pkg/devguard"
	parser "github.com/novln/docker-parser"
	"github.com/sirupsen/logrus"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/target"
)

type DevGuardTarget struct {
	apiUrl                 string
	token                  string
	tags                   []string
	assetNameAnnotationKey string

	rootProjectID    string
	rootProjectSlug  string
	organizationSlug string

	client devguard.HTTPClient
}

const (
	kubernetesCluster  = "kubernetes-cluster"
	sbomOperator       = "sbom-operator"
	rawImageId         = "raw-image-id"
	podNamespaceTagKey = "namespace"
)

func NewDevGuardTarget(token, apiUrl, rootProjectName string, tags []string) *DevGuardTarget {
	// fetch the root project id
	client := devguard.NewHTTPClient(token, apiUrl)

	arr := strings.Split(rootProjectName, "/")
	if len(arr) != 2 {
		logrus.Fatalf("Invalid root project name: %s. Needs to be <organization slug>/<project slug>", rootProjectName)
	}

	return &DevGuardTarget{
		apiUrl: apiUrl,
		token:  token,
		tags:   tags,

		rootProjectSlug:  arr[1],
		organizationSlug: arr[0],
		client:           client,
	}
}

func (g *DevGuardTarget) ValidateConfig() error {
	if g.token == "" {
		return fmt.Errorf("%s is empty", internal.ConfigDevGuardToken)
	}

	if g.apiUrl == "" {
		return fmt.Errorf("%s is empty", internal.ConfigDevGuardApiURL)
	}

	if len(g.tags) == 0 {
		g.tags = []string{"kubernetes-cluster"}
	}

	return nil
}

func (g *DevGuardTarget) Initialize() error {
	// set the root project id
	rootProjectID, err := g.getProjectID(g.rootProjectSlug)
	if err != nil {
		return err
	}

	g.rootProjectID = rootProjectID
	return nil
}

func (g *DevGuardTarget) getProjectID(slug string) (string, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("/api/v1/organizations/%s/projects/%s/", g.organizationSlug, slug), nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := g.client.Do(req)

	if err != nil {
		return "", err
	}

	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}

	var project map[string]interface{}
	// parse the response body
	err = json.NewDecoder(resp.Body).Decode(&project)
	if err != nil {
		return "", err
	}

	return project["id"].(string), nil
}

func (g *DevGuardTarget) getAssetBySlug(projectSlug, slug string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("/api/v1/organizations/%s/projects/%s/assets/%s/", g.organizationSlug, projectSlug, slug), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := g.client.Do(req)

	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("Asset not found")
	}

	var asset map[string]interface{}
	// parse the response body
	err = json.NewDecoder(resp.Body).Decode(&asset)
	if err != nil {
		return nil, err
	}

	return asset, nil
}

func (g *DevGuardTarget) createAssetInsideProject(projectSlug string, assetName string) (map[string]interface{}, error) {
	// the asset does not exist, create it
	createRequestBody := map[string]interface{}{
		"name":        assetName,
		"description": fmt.Sprintf("Controlled by an Kubernetes Operator. Asset %s", assetName),
	}

	// to json
	jsonBody, err := json.Marshal(createRequestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("/api/v1/organizations/%s/projects/%s/assets/", g.organizationSlug, projectSlug), bytes.NewReader(jsonBody))

	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}

	// parse the response body
	var asset map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&asset)
	if err != nil {
		return nil, err
	}

	return asset, nil
}

func (g *DevGuardTarget) createChildNamespaceProject(namespace string) (map[string]interface{}, error) {
	// the project does not exist, create it
	createRequestBody := map[string]interface{}{
		"name":        namespace,
		"description": fmt.Sprintf("Controlled by an Kubernetes Operator. Namespace %s", namespace),
		"parentId":    g.rootProjectID,
		"type":        "kubernetesNamespace",
	}

	// to json
	jsonBody, err := json.Marshal(createRequestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("/api/v1/organizations/%s/projects/"), bytes.NewReader(jsonBody))

	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}

	// parse the response body
	var project map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&project)
	if err != nil {
		return nil, err
	}

	return project, nil
}

func (g *DevGuardTarget) LoadImages() ([]target.ImageInNamespace, error) {
	// fetch all projects inside the root project
	req, err := http.NewRequest("GET", fmt.Sprintf("/api/v1/organizations/%s/projects?parentId=%s", g.organizationSlug, g.rootProjectID), nil)
	if err != nil {
		logrus.Errorf("Could not fetch projects: %v", err)
		return nil, err
	}

	// check all subprojects
	// for each subproject, iterate over all assets.
	var res []map[string]interface{}
	resp, err := g.client.Do(req)
	if err != nil {
		logrus.Errorf("Could not fetch projects: %v", err)
		return nil, err
	}

	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		logrus.Errorf("Could not fetch projects: %v", err)
		return nil, err
	}

	// fetch all assets for each project.
	// we can do that concurrently
	wg := sync.WaitGroup{}

	// channel to collect all images
	images := make(chan target.ImageInNamespace)

	for _, project := range res {
		wg.Add(1)
		go func(project map[string]interface{}) {
			defer wg.Done()
			// fetch all assets
			req, err := http.NewRequest("GET", fmt.Sprintf("/api/v1/organizations/%s/projects/%s/assets/", g.organizationSlug, project["slug"].(string)), nil)
			if err != nil {
				logrus.Errorf("Could not fetch assets: %v", err)
				return
			}

			resp, err := g.client.Do(req)
			if err != nil {
				logrus.Errorf("Could not fetch assets: %v", err)
				return
			}

			var assets []map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&assets)
			if err != nil {
				logrus.Errorf("Could not fetch assets: %v", err)
				return
			}

			for _, asset := range assets {
				images <- target.ImageInNamespace{
					Namespace: project["name"].(string),
					Image: &libk8s.RegistryImage{
						ImageID: asset["name"].(string),
						Image:   asset["name"].(string),
					},
				}
			}
		}(project)
	}

	go func() {
		wg.Wait()
		close(images)
	}()

	var imagesInNamespace []target.ImageInNamespace = []target.ImageInNamespace{}

	for img := range images {
		imagesInNamespace = append(imagesInNamespace, img)
	}

	return imagesInNamespace, nil
}

func (g *DevGuardTarget) ProcessSbom(ctx *target.TargetContext) error {
	assetName := ""
	version := ""

	logrus.Debugf("%v", g)

	// Set custom project name by kubernetes annotation?
	if g.assetNameAnnotationKey != "" {
		logrus.Debugf(`Try to set project name by configured annotationkey "%s"`, g.assetNameAnnotationKey)
		for podAnnotationKey, podAnnotationValue := range ctx.Pod.Annotations {
			if strings.HasPrefix(podAnnotationKey, g.assetNameAnnotationKey) {
				if podAnnotationValue != "" {
					// determine container name from annotation key
					containerName := getContainerNameFromAnnotationKey(podAnnotationKey, "/")
					if containerName != "" {
						logrus.Debugf(`ContainerName found: "%s"`, containerName)
						// correct container?
						if containerName == ctx.Container.Name {
							assetName, version = getNameAndVersionFromString(podAnnotationValue, ":")
							logrus.Infof(`Custom project name found at annotation "%s" for container "%s": "%s:%s"`, podAnnotationKey, containerName, assetName, version)
							break
						}
					} else {
						logrus.Errorf(`Containername could not be determined from annotation "%s". Skip setting project name.`, podAnnotationKey)
					}
				} else {
					logrus.Errorf(`Empty value for custom project name annotation "%s". Skip setting custom project name.`, podAnnotationKey)
				}
			}
		}
	}

	// If assetNameAnnotationKey is not set or could not be parsed correctly, use image instead
	if assetName == "" || version == "" {
		assetName, version = getRepoWithVersion(ctx.Image)
	}

	if ctx.Sbom == "" {
		logrus.Infof("Empty SBOM - skip image (image=%s)", ctx.Image.ImageID)
		return nil
	}

	client := devguard.NewHTTPClient(g.token, g.apiUrl)
	// make sure the namespace project exists inside the root project
	slug := slug.Make(ctx.Pod.PodNamespace)
	_, err := g.getProjectID(slug)
	var project map[string]interface{}
	if err != nil {
		// the project does not exist yet
		// create it
		project, err = g.createChildNamespaceProject(ctx.Pod.PodNamespace)
		if err != nil {
			logrus.Errorf("Could not create project: %v", err)
			return err
		}
	}

	// check if the asset does already exist inside the project
	asset, err := g.getAssetBySlug(slug, assetName)
	if err != nil {
		// the asset does not exist yet
		// create it now
		asset, err = g.createAssetInsideProject(project["slug"].(string), assetName)
		if err != nil {
			logrus.Errorf("Could not create asset: %v", err)
			return err
		}
	}

	// asset exists now.
	// upload the SBOM to the asset
	req, err := http.NewRequest("POST", fmt.Sprintf("/api/v1/organizations/%s/projects/%s/assets/%s/scan/", g.organizationSlug, project["slug"].(string), asset["slug"].(string)), strings.NewReader(ctx.Sbom))
	if err != nil {
		logrus.Errorf("Could not upload BOM: %v", err)
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Risk-Management", "true")
	req.Header.Set("X-Asset-Name", assetName)
	req.Header.Set("X-Asset-Version", version)
	req.Header.Set("X-Scan-Type", "container-scanning")
	req.Header.Set("X-Scanner", "github.com/l3montree-dev/devguard-operator")

	logrus.Infof("Sending SBOM to DevGuard (assetName=%s, version=%s)", assetName, version)

	_, err = client.Do(req)
	if err != nil {
		logrus.Errorf("Could not upload BOM: %v", err)
		return err
	}

	logrus.Infof("Uploaded SBOM")
	return nil
}

func (g *DevGuardTarget) Remove(images []target.ImageInNamespace) error {

	wg := sync.WaitGroup{}
	for _, img := range images {
		wg.Add(1)
		go func(img target.ImageInNamespace) {
			defer wg.Done()
			// archive the asset
			reqBody := map[string]interface{}{
				"archived": true,
			}

			jsonBytes := new(bytes.Buffer)
			err := json.NewEncoder(jsonBytes).Encode(reqBody)

			if err != nil {
				logrus.Errorf("Could not archive asset: %v", err)
				return
			}

			req, err := http.NewRequest("PATCH", fmt.Sprintf("/api/v1/organizations/%s/projects/%s/assets/%s/", g.organizationSlug, img.Namespace, img.Image.ImageID), jsonBytes)
			if err != nil {
				logrus.Errorf("Could not archive asset: %v", err)
				return
			}

			req.Header.Set("Content-Type", "application/json")
			_, err = g.client.Do(req)
			if err != nil {
				logrus.Errorf("Could not archive asset: %v", err)
				return
			}
		}(img)
	}

	wg.Wait()

	// check if there are empty projects now. We can archive those too
	namespaces := map[string]bool{}
	for _, img := range images {
		namespaces[img.Namespace] = true
	}

	wg = sync.WaitGroup{}
	// fetch all assets of those projects.
	// if empty, archive the project
	for namespace := range namespaces {
		wg.Add(1)
		go func(namespace string) {
			defer wg.Done()
			req, err := http.NewRequest("GET", fmt.Sprintf("/api/v1/organizations/%s/projects/%s/assets/", g.organizationSlug, namespace), nil)
			if err != nil {
				logrus.Errorf("Could not fetch assets: %v", err)
				return
			}

			resp, err := g.client.Do(req)
			if err != nil {
				logrus.Errorf("Could not fetch assets: %v", err)
				return
			}

			var assets []map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&assets)
			if err != nil {
				logrus.Errorf("Could not fetch assets: %v", err)
				return
			}

			if len(assets) == 0 {
				// archive this project
				reqBody := map[string]interface{}{
					"archived": true,
				}

				jsonBytes := new(bytes.Buffer)
				err := json.NewEncoder(jsonBytes).Encode(reqBody)

				if err != nil {
					logrus.Errorf("Could not archive project: %v", err)
					return
				}

				req, err := http.NewRequest("PATCH", fmt.Sprintf("/api/v1/organizations/%s/projects/%s/", g.organizationSlug, namespace), jsonBytes)
				if err != nil {
					logrus.Errorf("Could not archive project: %v", err)
					return
				}

				req.Header.Set("Content-Type", "application/json")
				_, err = g.client.Do(req)
				if err != nil {
					logrus.Errorf("Could not archive project: %v", err)
					return
				}

				logrus.Infof("Archived project %s", namespace)
			}
		}(namespace)
	}

	wg.Wait()
	return nil
}

func getNameAndVersionFromString(input string, delimiter string) (string, string) {
	parts := strings.Split(input, delimiter)
	name := parts[0]
	version := "latest"
	if len(parts) == 2 {
		version = parts[1]
	}
	return name, version
}

func getContainerNameFromAnnotationKey(annotationKey string, delimiter string) string {
	parts := strings.Split(annotationKey, delimiter)
	containerName := ""
	if len(parts) == 2 {
		containerName = parts[1]
	}
	return containerName
}

func getRepoWithVersion(image *libk8s.RegistryImage) (string, string) {
	imageRef, err := parser.Parse(image.ImageID)
	if err != nil {
		logrus.WithError(err).Errorf("Could not parse image %s", image.ImageID)
		return "", ""
	}

	projectName := imageRef.Repository()

	if strings.Index(image.Image, "sha256") != 0 {
		imageRef, err = parser.Parse(image.Image)
		if err != nil {
			logrus.WithError(err).Errorf("Could not parse image %s", image.Image)
			return "", ""
		}
	}

	version := imageRef.Tag()
	return projectName, version
}
