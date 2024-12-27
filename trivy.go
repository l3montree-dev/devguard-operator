package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"time"

	"github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/l3montree-dev/devguard-operator/kubernetes"
	"github.com/pkg/errors"
	"oras.land/oras-go/v2"
	orasOci "oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
)

type Trivy struct {
	resolveVersion   func() string
	proxyRegistryMap map[string]string
	appVersion       string
}

func NewTrivyScanner(proxyRegistryMap map[string]string, appVersion string) *Trivy {
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

func (t Trivy) downloadImageToLocalFilesystem(img *oci.RegistryImage) (string, error) {
	// Convert credentials if needed (these can be used via Docker login or environment).
	credentials := oci.ConvertSecrets(*img, t.proxyRegistryMap)
	// use oras to download the image
	tmpDir, err := os.MkdirTemp("", "oras")

	if err != nil {
		return "", errors.Wrap(err, "could not create temp directory")
	}

	store, err := orasOci.New(tmpDir)

	if err != nil {
		return "", errors.Wrap(err, "could not create OCI layout store")
	}

	ctx := context.Background()

	repoName, tag := getRepoWithVersion(img)
	repo, err := remote.NewRepository(repoName)
	if err != nil {
		return "", errors.Wrap(err, "could not create remote repository")
	}
	if len(credentials) > 0 {
		repo.Client = &auth.Client{
			Client: retry.DefaultClient,
			Cache:  auth.NewCache(),
			Credential: auth.StaticCredential(credentials[0].Authority, auth.Credential{
				Username: credentials[0].Username,
				Password: credentials[0].Password,
			}),
		}
	}

	_, err = oras.Copy(ctx, repo, tag, store, tag, oras.DefaultCopyOptions)
	if err != nil {
		return "", errors.Wrap(err, "could not copy image")
	}

	return tmpDir, nil
}

// ExecuteTrivy scans the provided image with Trivy and returns its CycloneDX SBOM.
func (t *Trivy) ExecuteTrivy(img *oci.RegistryImage) (string, error) {
	slog.Info("executing Trivy", "image", img.Image)

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

	// Download the image to the local filesystem.
	tmpDir, err := t.downloadImageToLocalFilesystem(img)
	if err != nil {
		return "", fmt.Errorf("could not download image: %w", err)
	}

	defer os.RemoveAll(tmpDir)

	// Invoke Trivy in CycloneDX format directly, writing SBOM to stdout.
	var stdout, stderr bytes.Buffer

	// create a tmp file
	sbomFile, err := os.Create(tmpDir + "/sbom.json")
	if err != nil {
		return "", fmt.Errorf("could not create temp file: %w", err)
	}

	cmd := exec.CommandContext(context.Background(),
		"trivy", "image",
		"--format", "cyclonedx",
		"--output", sbomFile.Name(),
		"--input", tmpDir,
	)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		slog.Error("Trivy scan failed", "err", stderr.String())
		return "", fmt.Errorf("trivy command error: %w", err)
	}

	slog.Info("Trivy execution completed", "duration", time.Since(now).String(), "image", img.Image)

	// Read the SBOM from the temp file
	sbom, err := os.ReadFile(sbomFile.Name())
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
