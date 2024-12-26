package processor

import (
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	"github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/ckotzbauer/sbom-operator/internal/trivy"

	"github.com/ckotzbauer/sbom-operator/internal/target"
	"github.com/ckotzbauer/sbom-operator/internal/target/devguard"

	"k8s.io/client-go/tools/cache"

	corev1 "k8s.io/api/core/v1"
)

type Processor struct {
	K8s      *kubernetes.KubeClient
	trivy    *trivy.Trivy
	Targets  []target.Target
	imageMap map[string]bool
}

func New(k8s *kubernetes.KubeClient, triv *trivy.Trivy) *Processor {
	targets := initTargets()

	return &Processor{K8s: k8s, trivy: triv, Targets: targets, imageMap: make(map[string]bool)}
}

func (p *Processor) ListenForPods() {
	var informer cache.SharedIndexInformer
	informer, err := p.K8s.StartPodInformer(internal.OperatorConfig.PodLabelSelector, cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(old, new interface{}) {
			oldPod := old.(*corev1.Pod)
			newPod := new.(*corev1.Pod)
			oldInfo := p.K8s.Client.ExtractPodInfos(*oldPod)
			newInfo := p.K8s.Client.ExtractPodInfos(*newPod)

			var removedContainers []*libk8s.ContainerInfo
			newInfo.Containers, removedContainers = getChangedContainers(oldInfo, newInfo)
			p.scanPod(newInfo)

			p.cleanupImagesIfNeeded(newInfo.PodNamespace, removedContainers, informer.GetStore().List())
		},
		DeleteFunc: func(obj interface{}) {
			pod := obj.(*corev1.Pod)
			info := p.K8s.Client.ExtractPodInfos(*pod)

			p.cleanupImagesIfNeeded(info.PodNamespace, info.Containers, informer.GetStore().List())
		},
	})

	if err != nil {
		slog.Error("Can't listen for pod-changes.", "err", err)
		return
	}

	p.runInformerAsync(informer)
}

func (p *Processor) ProcessAllPods(pods []libk8s.PodInfo, allImages []target.ImageInNamespace) {
	p.executeScans(pods, allImages)
}

func getImageName(img *oci.RegistryImage) string {
	// remove the tag if exists
	if strings.Contains(img.Image, ":") {
		return strings.Split(img.Image, ":")[0]
	}

	return img.Image
}

func (p *Processor) scanPod(pod libk8s.PodInfo) {
	errOccurred := false
	p.K8s.InjectPullSecrets(pod)

	for _, container := range pod.Containers {
		alreadyScanned := p.imageMap[pod.PodNamespace+"/"+getImageName(container.Image)]
		if /*p.K8s.HasAnnotation(pod.Annotations, container) ||*/ alreadyScanned {
			slog.Debug("Image already scanned", "image", container.Image.Image)
			continue
		}

		p.imageMap[pod.PodNamespace+"/"+getImageName(container.Image)] = true
		sbom, err := p.trivy.ExecuteTrivy(container.Image)
		if err != nil {
			slog.Error("scan failed", "err", err)
			continue
		}

		for _, t := range p.Targets {
			err = t.ProcessSbom(target.NewContext(sbom, container.Image, container, &pod))
			errOccurred = errOccurred || err != nil
		}
	}

	if !errOccurred && len(pod.Containers) > 0 {
		p.K8s.UpdatePodAnnotation(pod)
	}
}

func initTargets() []target.Target {
	targets := make([]target.Target, 0)

	var err error

	t := devguard.NewDevGuardTarget(internal.OperatorConfig.DevGuardToken, internal.OperatorConfig.DevGuardApiURL, internal.OperatorConfig.DevGuardProjectID, nil)
	targets = append(targets, t)

	if err != nil {
		panic(err)
	}

	return targets
}

func (p *Processor) executeScans(pods []libk8s.PodInfo, allImages []target.ImageInNamespace) {
	for _, pod := range pods {
		p.scanPod(pod)
	}

	for _, t := range p.Targets {
		targetImages, err := t.LoadImages()

		if err != nil {
			slog.Error("Failed to load images from target", "err", err)
			continue
		}

		removableImages := make([]target.ImageInNamespace, 0)
		for _, t := range targetImages {
			if !containsImage(allImages, t) {
				removableImages = append(removableImages, t)
				delete(p.imageMap, t.String())

				slog.Debug("Image marked for removal", "image", t.String())
			}
		}

		if len(removableImages) > 0 {
			t.Remove(removableImages)
		}
	}
}

func getChangedContainers(oldPod, newPod libk8s.PodInfo) ([]*libk8s.ContainerInfo, []*libk8s.ContainerInfo) {
	addedContainers := make([]*libk8s.ContainerInfo, 0)
	removedContainers := make([]*libk8s.ContainerInfo, 0)
	for _, c := range newPod.Containers {
		if !containsContainerImage(oldPod.Containers, c.Image.ImageID) {
			addedContainers = append(addedContainers, c)
		}
	}

	for _, c := range oldPod.Containers {
		if !containsContainerImage(newPod.Containers, c.Image.ImageID) {
			removedContainers = append(removedContainers, c)
		}
	}

	return addedContainers, removedContainers
}

func containsImage(images []target.ImageInNamespace, image target.ImageInNamespace) bool {
	for _, i := range images {
		if i.String() == image.String() {
			return true
		}
	}

	return false
}

func containsContainerImage(containers []*libk8s.ContainerInfo, image string) bool {
	for _, c := range containers {
		if c.Image.ImageID == image {
			return true
		}
	}

	return false
}

func (p *Processor) cleanupImagesIfNeeded(namespace string, removedContainers []*libk8s.ContainerInfo, allPods []interface{}) {
	images := make([]target.ImageInNamespace, 0)

	for _, c := range removedContainers {
		found := false
		for _, po := range allPods {
			pod := po.(*corev1.Pod)
			info := p.K8s.Client.ExtractPodInfos(*pod)
			found = found || containsContainerImage(info.Containers, c.Image.ImageID)
		}

		if !found {
			imageWithNamespace := target.ImageInNamespace{Namespace: namespace, Image: c.Image}
			images = append(images, imageWithNamespace)
			delete(p.imageMap, imageWithNamespace.String())

			slog.Debug("Image marked for removal", "image", imageWithNamespace.String())

		}
	}

	if len(images) > 0 {
		for _, t := range p.Targets {
			t.Remove(images)
		}
	}
}

func (p *Processor) runInformerAsync(informer cache.SharedIndexInformer) {
	stop := make(chan struct{})
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		run := true
		for run {
			sig := <-sigs
			switch sig {
			case syscall.SIGTERM, syscall.SIGINT:
				slog.Info("Received signal to stop", "signal", sig)
				close(stop)
				run = false
			}
		}
	}()

	go func() {

		for _, t := range p.Targets {
			err := t.Initialize()
			if err != nil {
				slog.Error("Target could not be initialized", "err", err)
			}
		}

		slog.Info("Start pod-informer")
		informer.Run(stop)
		slog.Info("Pod-informer has stopped")
		os.Exit(0)
	}()

	go func() {
		slog.Info("Wait for cache to be synced")
		if !cache.WaitForCacheSync(stop, informer.HasSynced) {
			slog.Error("Timed out waiting for the cache to sync")
			panic("Timed out waiting for the cache to sync")
		}

		slog.Info("Finished cache sync")
		pods := informer.GetStore().List()
		missingPods := make([]libk8s.PodInfo, 0)
		allImages := make([]target.ImageInNamespace, 0)

		for _, t := range p.Targets {
			targetImages, err := t.LoadImages()

			if err != nil {
				slog.Error("Failed to load images from target", "err", err)
				continue
			}

			for _, po := range pods {
				pod := po.(*corev1.Pod)
				slog.Debug("Pod found", "pod", pod.Name, "namespace", pod.Namespace)
				info := p.K8s.Client.ExtractPodInfos(*pod)
				for _, c := range info.Containers {
					allImages = append(allImages, target.ImageInNamespace{Namespace: info.PodNamespace, Image: c.Image})
					if !containsImage(targetImages, target.ImageInNamespace{
						Image:     c.Image,
						Namespace: info.PodNamespace,
					}) {
						missingPods = append(missingPods, info)
						slog.Debug("Pod needs to be analyzed", "pod", info.PodName, "namespace", info.PodNamespace)
						break
					}
				}
			}
		}

		if len(missingPods) > 0 {
			slog.Info("Execute initial scans on missing pods", "amount", len(missingPods))
			p.executeScans(missingPods, allImages)
		}
	}()
}
