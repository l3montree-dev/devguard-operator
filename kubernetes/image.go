package kubernetes

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/ckotzbauer/libk8soci/pkg/oci"
	parser "github.com/novln/docker-parser"
	"github.com/novln/docker-parser/docker"
)

type ImageInNamespace struct {
	Namespace string
	Image     *oci.RegistryImage
}

func (i ImageInNamespace) String() string {
	// remove the tag from the image name
	if strings.Contains(i.Image.Image, ":") {
		return i.Namespace + "/" + strings.Split(i.Image.Image, ":")[0]
	}
	return i.Namespace + "/" + i.Image.Image
}

func ApplyProxyRegistry(img *oci.RegistryImage, log bool, registryProxyMap map[string]string) error {
	imageRef, err := parser.Parse(img.ImageID)
	if err != nil {
		slog.Error("Could not parse image", "err", err, "img", img.ImageID)
		return err
	}

	for registryToReplace, proxyRegistry := range registryProxyMap {
		if imageRef.Registry() == registryToReplace {
			shortName := strings.TrimPrefix(imageRef.ShortName(), docker.DefaultRepoPrefix)
			fullName := fmt.Sprintf("%s/%s", imageRef.Registry(), shortName)
			if strings.HasPrefix(imageRef.Tag(), "sha256") {
				fullName = fmt.Sprintf("%s@%s", fullName, imageRef.Tag())
			} else {
				fullName = fmt.Sprintf("%s:%s", fullName, imageRef.Tag())
			}

			img.ImageID = strings.ReplaceAll(fullName, registryToReplace, proxyRegistry)
			img.Image = strings.ReplaceAll(img.Image, registryToReplace, proxyRegistry)

			if log {
				slog.Debug("Applied Registry-Proxy %s", img.ImageID)
			}

			break
		}
	}

	return nil
}
