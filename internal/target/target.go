package target

import (
	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	"github.com/ckotzbauer/libk8soci/pkg/oci"
)

type TargetContext struct {
	Image     *oci.RegistryImage
	Container *libk8s.ContainerInfo
	Pod       *libk8s.PodInfo
	Sbom      string
}

type ImageInNamespace struct {
	Namespace string
	Image     *oci.RegistryImage
}

func (i ImageInNamespace) String() string {
	return i.Namespace + "/" + i.Image.ImageID
}

type Target interface {
	Initialize() error
	ValidateConfig() error
	ProcessSbom(ctx *TargetContext) error
	LoadImages() ([]ImageInNamespace, error)
	Remove(images []ImageInNamespace) error
}

func NewContext(sbom string, image *oci.RegistryImage, container *libk8s.ContainerInfo, pod *libk8s.PodInfo) *TargetContext {
	return &TargetContext{image, container, pod, sbom}
}
