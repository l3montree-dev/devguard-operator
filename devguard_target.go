package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/gosimple/slug"
	"github.com/l3montree-dev/devguard/pkg/devguard"
	parser "github.com/novln/docker-parser"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/l3montree-dev/devguard-operator/kubernetes"
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

func NewDevGuardTarget(token, apiUrl, rootProjectName string, tags []string) *DevGuardTarget {
	// fetch the root project id
	client := devguard.NewHTTPClient(token, apiUrl)

	arr := strings.Split(rootProjectName, "/")
	if len(arr) != 3 {
		slog.Error(fmt.Sprintf("invalid root project name: %s. Needs to be <organization slug>/projects/<project slug>", rootProjectName))
		panic(fmt.Sprintf("invalid root project name: %s. Needs to be <organization slug>/projects/<project slug>", rootProjectName))
	}

	return &DevGuardTarget{
		apiUrl: apiUrl,
		token:  token,
		tags:   tags,

		rootProjectSlug:  arr[2],
		organizationSlug: arr[0],
		client:           client,
	}
}

func (g *DevGuardTarget) ValidateConfig() error {
	if g.token == "" {
		return fmt.Errorf("%s is empty", ConfigDevGuardToken)
	}

	if g.apiUrl == "" {
		return fmt.Errorf("%s is empty", ConfigDevGuardApiURL)
	}

	if len(g.tags) == 0 {
		g.tags = []string{"kubernetes-cluster"}
	}

	return nil
}

func (g *DevGuardTarget) Initialize() error {
	// set the root project id
	rootProject, err := g.getProjectBySlug(g.rootProjectSlug)
	if err != nil {
		return err
	}

	g.rootProjectID = rootProject["id"].(string)

	// check if already marked as kubernetes cluster
	if rootProject["type"].(string) != "kubernetesCluster" {
		// update the project type
		body := map[string]interface{}{
			"type": "kubernetesCluster",
		}

		// to json
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return err
		}

		req, err := http.NewRequest("PATCH", fmt.Sprintf("/api/v1/organizations/%s/projects/%s/", g.organizationSlug, g.rootProjectSlug), bytes.NewBuffer(jsonBody))
		if err != nil {
			return err
		}

		req.Header.Set("Content-Type", "application/json")

		_, err = g.client.Do(req)
		if err != nil {
			return err
		}

		slog.Info("Updated root project to kubernetesCluster", "rootProjectSlug", g.rootProjectSlug)
	}

	return nil
}

func (g *DevGuardTarget) getProjectBySlug(slug string) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("/api/v1/organizations/%s/projects/%s/", g.organizationSlug, slug), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := g.client.Do(req)

	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("project not found")
	}

	var project map[string]interface{}
	// parse the response body
	err = json.NewDecoder(resp.Body).Decode(&project)
	if err != nil {
		return nil, err
	}

	return project, nil
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
		return nil, fmt.Errorf("asset not found")
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

		"confidentialityRequirement": "medium",
		"integrityRequirement":       "medium",
		"availabilityRequirement":    "medium",
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

	req, err := http.NewRequest("POST", fmt.Sprintf("/api/v1/organizations/%s/projects/", g.organizationSlug), bytes.NewReader(jsonBody))

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

func (g *DevGuardTarget) LoadImages() ([]kubernetes.ImageInNamespace, error) {
	// fetch all projects inside the root project
	req, err := http.NewRequest("GET", fmt.Sprintf("/api/v1/organizations/%s/projects?parentId=%s", g.organizationSlug, g.rootProjectID), nil)
	if err != nil {
		slog.Error("Could not fetch projects", "err", err)
		return nil, err
	}

	// check all subprojects
	// for each subproject, iterate over all assets.
	var res []map[string]interface{}
	resp, err := g.client.Do(req)
	if err != nil {
		slog.Error("Could not fetch projects", "err", err)
		return nil, err
	}

	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		slog.Error("Could not fetch projects", "err", err)
		return nil, err
	}

	for el := range res {
		slog.Info("Project", "name", res[el]["name"])
	}

	// fetch all assets for each project.
	// we can do that concurrently
	wg := sync.WaitGroup{}

	// channel to collect all images
	images := make(chan kubernetes.ImageInNamespace)

	for _, project := range res {
		wg.Add(1)
		go func(project map[string]interface{}) {
			defer wg.Done()
			// fetch all assets
			req, err := http.NewRequest("GET", fmt.Sprintf("/api/v1/organizations/%s/projects/%s/assets/", g.organizationSlug, project["slug"].(string)), nil)
			if err != nil {
				slog.Error("Could not fetch assets", "err", err)
				return
			}

			resp, err := g.client.Do(req)
			if err != nil {
				slog.Error("Could not fetch assets", "err", err)
				return
			}

			var assets []map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&assets)
			if err != nil {
				slog.Error("Could not fetch assets", "err", err)
				return
			}

			for _, asset := range assets {
				images <- kubernetes.ImageInNamespace{
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

	var imagesInNamespace []kubernetes.ImageInNamespace = []kubernetes.ImageInNamespace{}

	for img := range images {
		imagesInNamespace = append(imagesInNamespace, img)
	}

	return imagesInNamespace, nil
}

func (g *DevGuardTarget) ProcessSbom(ctx *TargetContext) error {
	assetName := ""
	version := ""

	// Set custom project name by kubernetes annotation?
	if g.assetNameAnnotationKey != "" {
		slog.Debug(`Try to set project name by configured annotationkey`, "assetNameAnnotationKey", g.assetNameAnnotationKey)
		for podAnnotationKey, podAnnotationValue := range ctx.Pod.Annotations {
			if strings.HasPrefix(podAnnotationKey, g.assetNameAnnotationKey) {
				if podAnnotationValue != "" {
					// determine container name from annotation key
					containerName := getContainerNameFromAnnotationKey(podAnnotationKey, "/")
					if containerName != "" {
						slog.Debug(`ContainerName found"`, "name", containerName)
						// correct container?
						if containerName == ctx.Container.Name {
							assetName, version = getNameAndVersionFromString(podAnnotationValue, ":")
							slog.Info(`Custom project name found`, "podAnnotationKey", podAnnotationKey, "containerName", containerName, "assetName", assetName, "version", version)
							break
						}
					} else {
						slog.Error(`Containername could not be determined from annotation. Skip setting project name.`, "podAnnotationKey", podAnnotationKey)

					}
				} else {
					slog.Error(`Empty value for custom project name annotation. Skip setting custom project name.`, "podAnnotationKey", podAnnotationKey)
				}
			}
		}
	}

	// If assetNameAnnotationKey is not set or could not be parsed correctly, use image instead
	if assetName == "" || version == "" {
		assetName, version = getRepoWithVersion(ctx.Image)
	}

	if ctx.Sbom == "" {
		slog.Info("Empty SBOM - skip image", "image", ctx.Image.ImageID)
		return nil
	}

	client := devguard.NewHTTPClient(g.token, g.apiUrl)
	// make sure the namespace project exists inside the root project
	s := slug.Make(ctx.Pod.PodNamespace)
	project, err := g.getProjectBySlug(s)

	slog.Debug("checking project existence", "projectSlug", s, "err", err, "project", project)
	if err != nil {
		// the project does not exist yet
		// create it
		slog.Debug("Creating project", "projectSlug", s)
		project, err = g.createChildNamespaceProject(s)
		if err != nil {
			slog.Error("Could not create project", "err", err)
			return err
		}
	}

	// check if the asset does already exist inside the project
	asset, err := g.getAssetBySlug(s, slug.Make(assetName))
	if err != nil {
		// the asset does not exist yet
		// create it now
		asset, err = g.createAssetInsideProject(project["slug"].(string), assetName)
		if err != nil {
			slog.Error("Could not create asset", "err", err)
			return err
		}
	}

	// asset exists now.
	// upload the SBOM to the asset
	req, err := http.NewRequest("POST", "/api/v1/scan/", strings.NewReader(ctx.Sbom))
	if err != nil {
		slog.Error("Could not upload BOM", "err", err)
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Risk-Management", "true")
	req.Header.Set("X-Asset-Name", fmt.Sprintf("%s/projects/%s/assets/%s", g.organizationSlug, s, asset["slug"].(string)))
	req.Header.Set("X-Asset-Version", version)
	req.Header.Set("X-Scan-Type", "container-scanning")
	req.Header.Set("X-Scanner", "github.com/l3montree-dev/devguard-operator")

	slog.Info("Sending SBOM to DevGuard", "assetName", assetName, "version", version)

	_, err = client.Do(req)
	if err != nil {
		slog.Error("Could not upload BOM", "err", err)
		return err
	}

	slog.Info("Uploaded SBOM to DevGuard", "assetName", assetName, "version", version)
	return nil
}

func (g *DevGuardTarget) Remove(images []kubernetes.ImageInNamespace) error {

	wg := sync.WaitGroup{}

	for _, img := range images {
		wg.Add(1)
		go func(img kubernetes.ImageInNamespace) {
			defer wg.Done()

			name, _ := getRepoWithVersion(img.Image)

			projectSlug := slug.Make(img.Namespace)
			assetSlug := slug.Make(name)

			req, err := http.NewRequest("DELETE", fmt.Sprintf("/api/v1/organizations/%s/projects/%s/assets/%s/", g.organizationSlug, projectSlug, assetSlug), nil)
			if err != nil {
				slog.Error("could not delete asset", "err", err)
				return
			}

			slog.Info("Deleting asset", "projectSlug", projectSlug, "assetSlug", assetSlug)

			req.Header.Set("Content-Type", "application/json")
			_, err = g.client.Do(req)
			if err != nil {
				slog.Error("could not delete asset", "err", err)
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
			projectSlug := slug.Make(namespace)

			req, err := http.NewRequest("GET", fmt.Sprintf("/api/v1/organizations/%s/projects/%s/assets/", g.organizationSlug, projectSlug), nil)
			if err != nil {
				slog.Error("Could not fetch assets", "err", err)
				return
			}

			resp, err := g.client.Do(req)
			if err != nil {
				slog.Error("Could not fetch assets", "err", err)
				return
			}

			var assets []map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&assets)
			if err != nil {
				slog.Error("Could not fetch assets", "err", err)
				return
			}

			if len(assets) == 0 {
				req, err := http.NewRequest("DELETE", fmt.Sprintf("/api/v1/organizations/%s/projects/%s/", g.organizationSlug, projectSlug), nil)
				if err != nil {
					slog.Error("Could not delete project", "err", err)
					return
				}

				req.Header.Set("Content-Type", "application/json")
				_, err = g.client.Do(req)
				if err != nil {
					slog.Error("Could not delete project", "err", err)
					return
				}

				slog.Info("Deleted project", "projectSlug", projectSlug)
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
	imageRef, err := parser.Parse(image.Image)
	if err != nil {
		slog.Error("Could not parse image", "image", image.Image)
		return "", ""
	}

	projectName := imageRef.Repository()

	if strings.Index(image.Image, "sha256") != 0 {
		imageRef, err = parser.Parse(image.Image)
		if err != nil {
			slog.Error("Could not parse image", "image", image.Image)
			return "", ""
		}
	}

	version := imageRef.Tag()
	return projectName, version
}
