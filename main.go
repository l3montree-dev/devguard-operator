package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/ckotzbauer/libstandard"
	"github.com/l3montree-dev/devguard-operator/internal"
	"github.com/l3montree-dev/devguard-operator/internal/daemon"
	"github.com/l3montree-dev/devguard-operator/internal/kubernetes"
	"github.com/l3montree-dev/devguard-operator/internal/processor"
	"github.com/l3montree-dev/devguard-operator/internal/trivy"

	"github.com/lmittmann/tint"
	"github.com/spf13/cobra"
)

// InitLogger initializes the logger with a tint handler.
// tint is a simple logging library that allows to add colors to the log output.
// this is obviously not required, but it makes the logs easier to read.
func initLogger() {
	// slog.HandlerOptions
	w := os.Stderr

	// set global logger with custom options
	slog.SetDefault(slog.New(
		tint.NewHandler(w, &tint.Options{
			Level:      slog.LevelDebug,
			TimeFormat: time.Kitchen,
			AddSource:  true,
		}),
	))
}

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
				triv := trivy.New(libstandard.ToMap(internal.OperatorConfig.RegistryProxies), Version)
				p := processor.New(k8s, triv)
				p.ListenForPods()
			}

			slog.Info("webserver is running at port 8081")
			http.HandleFunc("/health", health)

			server := &http.Server{
				Addr:              ":8081",
				ReadHeaderTimeout: 3 * time.Second,
			}

			slog.Error("starting webserver failed", "err", server.ListenAndServe())
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
	slog.Info("starting devguard-operator", "version", Version, "commit", Commit, "date", Date, "builtBy", BuiltBy, "goVersion", runtime.Version())
}

func health(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(200)
	fmt.Fprint(w, "Running!")
}

func main() {
	initLogger()

	rootCmd := newRootCmd()
	err := rootCmd.Execute()
	if err != nil {
		panic(err)
	}
}
