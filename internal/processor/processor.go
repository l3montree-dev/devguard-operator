package processor

import (
	"os"
	"os/signal"
	"syscall"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/ckotzbauer/sbom-operator/internal/syft"
	"github.com/ckotzbauer/sbom-operator/internal/target"
	"github.com/ckotzbauer/sbom-operator/internal/target/devguard"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"

	corev1 "k8s.io/api/core/v1"
)

type Processor struct {
	K8s      *kubernetes.KubeClient
	sy       *syft.Syft
	Targets  []target.Target
	imageMap map[string]bool
}

func New(k8s *kubernetes.KubeClient, sy *syft.Syft) *Processor {
	targets := initTargets(k8s)

	return &Processor{K8s: k8s, sy: sy, Targets: targets, imageMap: make(map[string]bool)}
}

func (p *Processor) ListenForPods() {
	var informer cache.SharedIndexInformer
	informer, err := p.K8s.StartPodInformer(internal.OperatorConfig.PodLabelSelector, cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(old, new interface{}) {
			oldPod := old.(*corev1.Pod)
			newPod := new.(*corev1.Pod)
			oldInfo := p.K8s.Client.ExtractPodInfos(*oldPod)
			newInfo := p.K8s.Client.ExtractPodInfos(*newPod)
			logrus.Tracef("Pod %s/%s was updated.", newInfo.PodNamespace, newInfo.PodName)

			var removedContainers []*libk8s.ContainerInfo
			newInfo.Containers, removedContainers = getChangedContainers(oldInfo, newInfo)
			p.scanPod(newInfo)

			p.cleanupImagesIfNeeded(newInfo.PodNamespace, removedContainers, informer.GetStore().List())
		},
		DeleteFunc: func(obj interface{}) {
			pod := obj.(*corev1.Pod)
			info := p.K8s.Client.ExtractPodInfos(*pod)
			logrus.Tracef("Pod %s/%s was removed.", info.PodNamespace, info.PodName)
			p.cleanupImagesIfNeeded(info.PodNamespace, info.Containers, informer.GetStore().List())
		},
	})

	if err != nil {
		logrus.WithError(err).Fatal("Can't listen for pod-changes.")
		return
	}

	p.runInformerAsync(informer)
}

func (p *Processor) ProcessAllPods(pods []libk8s.PodInfo, allImages []target.ImageInNamespace) {
	p.executeSyftScans(pods, allImages)
}

func (p *Processor) scanPod(pod libk8s.PodInfo) {
	errOccurred := false
	p.K8s.InjectPullSecrets(pod)

	for _, container := range pod.Containers {
		alreadyScanned := p.imageMap[container.Image.ImageID]
		if p.K8s.HasAnnotation(pod.Annotations, container) || alreadyScanned {
			logrus.Debugf("Skip image %s", container.Image.ImageID)
			continue
		}

		p.imageMap[container.Image.ImageID] = true
		sbom, err := p.sy.ExecuteSyft(container.Image)
		if err != nil {
			// Error is already handled from syft module.
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

func initTargets(k8s *kubernetes.KubeClient) []target.Target {
	targets := make([]target.Target, 0)

	var err error

	t := devguard.NewDevGuardTarget(internal.OperatorConfig.DevGuardToken, internal.OperatorConfig.DevGuardApiURL, internal.OperatorConfig.DevGuardProjectID, nil)
	targets = append(targets, t)

	if err != nil {
		logrus.WithError(err).Fatal("Config-Validation failed!")
	}

	if len(targets) == 0 {
		logrus.Fatalf("Please specify at least one target.")
	}

	return targets
}

func (p *Processor) executeSyftScans(pods []libk8s.PodInfo, allImages []target.ImageInNamespace) {
	for _, pod := range pods {
		p.scanPod(pod)
	}

	for _, t := range p.Targets {
		targetImages, err := t.LoadImages()

		if err != nil {
			logrus.WithError(err).Error("Failed to load images from target")
			continue
		}

		removableImages := make([]target.ImageInNamespace, 0)
		for _, t := range targetImages {
			if !containsImage(allImages, t) {
				removableImages = append(removableImages, t)
				delete(p.imageMap, t.String())
				logrus.Debugf("Image %s marked for removal", t.String())
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
		if i.Image.Image == i.Image.Image && i.Namespace == image.Namespace {
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
			images = append(images, target.ImageInNamespace{Namespace: namespace, Image: c.Image})
			delete(p.imageMap, c.Image.ImageID)
			logrus.Debugf("Image %s marked for removal", c.Image.ImageID)
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
				logrus.Infof("Received signal %s", sig)
				close(stop)
				run = false
			}
		}
	}()

	go func() {

		for _, t := range p.Targets {
			err := t.Initialize()
			if err != nil {
				logrus.WithError(err).Fatal("Target could not be initialized,")
			}
		}

		logrus.Info("Start pod-informer")
		informer.Run(stop)
		logrus.Info("Pod-informer has stopped")
		os.Exit(0)
	}()

	go func() {
		logrus.Info("Wait for cache to be synced")
		if !cache.WaitForCacheSync(stop, informer.HasSynced) {
			logrus.Fatal("Timed out waiting for the cache to sync")
		}

		logrus.Info("Finished cache sync")
		pods := informer.GetStore().List()
		missingPods := make([]libk8s.PodInfo, 0)
		allImages := make([]target.ImageInNamespace, 0)

		for _, t := range p.Targets {
			targetImages, err := t.LoadImages()
			if err != nil {
				logrus.WithError(err).Error("Failed to load images from target")
				continue
			}

			for _, po := range pods {
				pod := po.(*corev1.Pod)
				info := p.K8s.Client.ExtractPodInfos(*pod)
				for _, c := range info.Containers {
					allImages = append(allImages, target.ImageInNamespace{Namespace: info.PodNamespace, Image: c.Image})
					if !containsImage(targetImages, target.ImageInNamespace{
						Image:     c.Image,
						Namespace: info.PodNamespace,
					}) && !p.K8s.HasAnnotation(info.Annotations, c) {
						missingPods = append(missingPods, info)
						logrus.Debugf("Pod %s/%s needs to be analyzed", info.PodNamespace, info.PodName)
						break
					}
				}
			}
		}

		if len(missingPods) > 0 {
			p.executeSyftScans(missingPods, allImages)
		}
	}()
}
