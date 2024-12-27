package trivy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/gosimple/slug"
	"github.com/l3montree-dev/devguard-operator/internal/kubernetes"
)

type Trivy struct {
	resolveVersion   func() string
	proxyRegistryMap map[string]string
	appVersion       string
}

func New(proxyRegistryMap map[string]string, appVersion string) *Trivy {
	return &Trivy{
		resolveVersion:   getTrivyVersion,
		proxyRegistryMap: proxyRegistryMap,
		appVersion:       appVersion,
	}
}

func (t Trivy) WithTrivyVersion(version string) Trivy {
	t.resolveVersion = func() string { return version }
	return t
}

// ExecuteTrivy scans the provided image with Trivy and returns its CycloneDX SBOM.
func (t *Trivy) ExecuteTrivy(img *oci.RegistryImage) (string, error) {
	slog.Info("Executing Trivy", "image", img.Image)

	originalImage := img.Image
	originalImageID := img.ImageID

	// Apply any configured proxy registry overrides.
	if err := kubernetes.ApplyProxyRegistry(img, true, t.proxyRegistryMap); err != nil {
		return "", err
	}

	// Revert image info to the original values after scanning.
	defer func() {
		img.Image = originalImage
		img.ImageID = originalImageID
	}()

	now := time.Now()

	// Convert credentials if needed (these can be used via Docker login or environment).
	_ = oci.ConvertSecrets(*img, t.proxyRegistryMap)

	// Invoke Trivy in CycloneDX format directly, writing SBOM to stdout.
	var stdout, stderr bytes.Buffer

	// create a tmp file
	tmpFile, err := os.CreateTemp("", slug.Make(img.Image))
	if err != nil {
		return "", fmt.Errorf("could not create temp file: %w", err)
	}

	defer os.Remove(tmpFile.Name())

	cmd := exec.CommandContext(context.Background(),
		"trivy", "image",
		"--quiet",
		"--format", "cyclonedx",
		"--output", tmpFile.Name(),
		img.Image,
	)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		slog.Error("Trivy scan failed", "err", stderr.String())
		return "", fmt.Errorf("trivy command error: %w", err)
	}

	slog.Info("Trivy execution completed", "duration", time.Since(now).String(), "image", img.Image)

	// Read the SBOM from the temp file
	sbom, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		return "", fmt.Errorf("could not read temp file: %w", err)
	}

	return string(sbom), nil
}

// getTrivyVersion tries to read the Trivy version from build info (if included).
func getTrivyVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		slog.Warn("failed to read build info")
		return ""
	}
	for _, dep := range bi.Deps {
		if strings.Contains(strings.ToLower(dep.Path), "trivy") {
			return dep.Version
		}
	}
	return ""
}

// removeTempContents clears files from /tmp (if needed, e.g. leftover scan data).
func removeTempContents() error {
	dir := "/tmp"
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer closeOrLog(d)
	names, err := d.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := os.RemoveAll(filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}

func closeOrLog(c io.Closer) {
	if err := c.Close(); err != nil {
		slog.Error("Could not close file", "err", err)
	}
}
