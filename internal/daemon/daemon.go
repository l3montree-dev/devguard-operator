package daemon

import (
	"log/slog"
	"time"

	"github.com/ckotzbauer/libstandard"
	"github.com/l3montree-dev/devguard-operator/internal"
	"github.com/l3montree-dev/devguard-operator/internal/kubernetes"
	"github.com/l3montree-dev/devguard-operator/internal/processor"
	"github.com/l3montree-dev/devguard-operator/internal/trivy"

	"github.com/robfig/cron"
)

type CronService struct {
	cron      string
	processor *processor.Processor
}

var running = false

func Start(cronTime string, appVersion string) {
	cr := libstandard.Unescape(cronTime)
	slog.Debug("settings cron", "cronTime", cronTime)

	k8s := kubernetes.NewClient(internal.OperatorConfig.IgnoreAnnotations, internal.OperatorConfig.FallbackPullSecret)
	triv := trivy.New(libstandard.ToMap(internal.OperatorConfig.RegistryProxies), appVersion)
	processor := processor.New(k8s, triv)

	cs := CronService{cron: cr, processor: processor}
	cs.printNextExecution()

	c := cron.New()
	err := c.AddFunc(cr, func() { cs.runBackgroundService() })
	if err != nil {
		slog.Error("could not configure cron", "err", err)
		return
	}

	c.Start()
}

func (c *CronService) printNextExecution() {
	s, err := cron.Parse(c.cron)
	if err != nil {
		slog.Error("could not parse cron", "err", err)
		return
	}

	nextRun := s.Next(time.Now())

	slog.Info("Next execution", "time", nextRun.Format(time.RFC3339))
}

func (c *CronService) runBackgroundService() {
	if running {
		return
	}

	running = true
	slog.Info("Execute background-service")

	for _, t := range c.processor.Targets {
		err := t.Initialize()
		if err != nil {
			slog.Error("Target could not be initialized", "err", err)
			continue
		}

		t.LoadImages()
	}

	namespaceSelector := internal.OperatorConfig.NamespaceLabelSelector
	namespaces, err := c.processor.K8s.Client.ListNamespaces(namespaceSelector)
	if err != nil {
		slog.Error("failed to list namespaces", "err", err)
		running = false
		return
	}

	slog.Debug("Discovered namespaces", "namespaces", namespaces)

	pods, allImages := c.processor.K8s.LoadImageInfos(namespaces, internal.OperatorConfig.PodLabelSelector)
	c.processor.ProcessAllPods(pods, allImages)

	c.printNextExecution()
	running = false
}
