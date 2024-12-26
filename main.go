package main

import (
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/ckotzbauer/libstandard"
	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/daemon"
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/ckotzbauer/sbom-operator/internal/processor"
	"github.com/ckotzbauer/sbom-operator/internal/syft"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	// Version sets the current Operator version
	Version = "0.0.1"
	Commit  = "main"
	Date    = ""
	BuiltBy = ""
)

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "devguard-operator",
		Short: "An operator for cataloguing all k8s-cluster-images to devguard.",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			internal.OperatorConfig = &internal.Config{}
			return libstandard.DefaultInitializer(internal.OperatorConfig, cmd, "devguard-operator")
		},
		Run: func(cmd *cobra.Command, args []string) {
			printVersion()

			if internal.OperatorConfig.Cron != "" {
				daemon.Start(internal.OperatorConfig.Cron, Version)
			} else {
				k8s := kubernetes.NewClient(internal.OperatorConfig.IgnoreAnnotations, internal.OperatorConfig.FallbackPullSecret)
				sy := syft.New(libstandard.ToMap(internal.OperatorConfig.RegistryProxies), Version)
				p := processor.New(k8s, sy)
				p.ListenForPods()
			}

			logrus.Info("Webserver is running at port 8080")
			http.HandleFunc("/health", health)

			server := &http.Server{
				Addr:              ":8080",
				ReadHeaderTimeout: 3 * time.Second,
			}

			logrus.WithError(server.ListenAndServe()).Fatal("Starting webserver failed!")
		},
	}

	libstandard.AddConfigFlag(rootCmd)
	libstandard.AddVerbosityFlag(rootCmd)
	rootCmd.PersistentFlags().String(internal.ConfigKeyCron, "", "Backround-Service interval (CRON)")

	rootCmd.PersistentFlags().Bool(internal.ConfigKeyIgnoreAnnotations, false, "Force analyzing of all images, including those from annotated pods.")

	rootCmd.PersistentFlags().String(internal.ConfigKeyPodLabelSelector, "", "Kubernetes Label-Selector for pods.")
	rootCmd.PersistentFlags().String(internal.ConfigKeyNamespaceLabelSelector, "", "Kubernetes Label-Selector for namespaces.")

	rootCmd.PersistentFlags().StringSlice(internal.ConfigKeyRegistryProxy, []string{}, "Registry-Proxy")
	rootCmd.PersistentFlags().Int64(internal.ConfigKeyJobTimeout, 60*60, "Job-Timeout")

	rootCmd.PersistentFlags().String(internal.ConfigDevGuardToken, "", "DevGuard-Token")
	rootCmd.PersistentFlags().String(internal.ConfigDevGuardApiURL, "", "DevGuard Api URL")
	rootCmd.PersistentFlags().String(internal.ConfigDevGuardProjectName, "", "DevGuard Project Name (eg. l3montree-cybersecurity/projects/devguard)")

	rootCmd.MarkPersistentFlagRequired(internal.ConfigDevGuardToken)
	rootCmd.MarkPersistentFlagRequired(internal.ConfigDevGuardProjectName)

	return rootCmd
}

func printVersion() {
	logrus.Info(fmt.Sprintf("Version: %s", Version))
	logrus.Info(fmt.Sprintf("Commit: %s", Commit))
	logrus.Info(fmt.Sprintf("Built at: %s", Date))
	logrus.Info(fmt.Sprintf("Built by: %s", BuiltBy))
	logrus.Info(fmt.Sprintf("Go Version: %s", runtime.Version()))
}

func health(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(200)
	fmt.Fprint(w, "Running!")
}

func main() {
	rootCmd := newRootCmd()
	err := rootCmd.Execute()
	if err != nil {
		panic(err)
	}
}
