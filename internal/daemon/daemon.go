package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ckotzbauer/sbom-git-operator/internal"
	"github.com/ckotzbauer/sbom-git-operator/internal/git"
	"github.com/ckotzbauer/sbom-git-operator/internal/kubernetes"
	"github.com/ckotzbauer/sbom-git-operator/internal/syft"
	"github.com/robfig/cron"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type CronService struct {
	cron string
}

func Start(cronTime string) {
	cr := internal.Unescape(cronTime)
	logrus.Debugf("Cron set to: %v", cr)

	cs := CronService{cron: cr}
	cs.printNextExecution()

	c := cron.New()
	c.AddFunc(cr, func() { cs.runBackgroundService() })
	c.Start()
}

func (c *CronService) printNextExecution() {
	s, err := cron.Parse(c.cron)
	if err != nil {
		logrus.WithError(err).Fatal("Cron cannot be parsed")
	}

	nextRun := s.Next(time.Now())
	logrus.Debugf("Next background-service run at: %v", nextRun)
}

func (c *CronService) runBackgroundService() {
	logrus.Info("Execute background-service")
	workingTree := viper.GetString("git-workingtree")

	gitAccount := git.New(viper.GetString("git-access-token"), viper.GetString("git-author-name"), viper.GetString("git-author-email"))
	gitAccount.PrepareRepository(viper.GetString("git-repository"), workingTree, viper.GetString("git-branch"))

	client := kubernetes.NewClient()
	namespaces := client.ListNamespaces(viper.GetString("namespace-label-selector"))
	logrus.Debugf("Discovered %v namespaces", len(namespaces))

	processedSbomFiles := []string{}

	for _, ns := range namespaces {
		pods := client.ListPods(ns.Name, viper.GetString("pod-label-selector"))
		logrus.Debugf("Discovered %v pods in namespace %v", len(pods), ns.Name)
		digests := client.GetContainerDigests(pods)

		for _, d := range digests {
			sbomPath := syft.ExecuteSyft(d, workingTree)
			processedSbomFiles = append(processedSbomFiles, sbomPath)
		}

		gitAccount.CommitAll(workingTree, fmt.Sprintf("Created new SBOMs for pods in namespace %s", ns.Name))
	}

	logrus.Debug("Start to remove old SBOMs")
	ignoreDirs := []string{".git"}
	err := filepath.Walk(workingTree, deleteObsoleteFiles(workingTree, ignoreDirs, processedSbomFiles, gitAccount))
	if err != nil {
		logrus.WithError(err).Error("Could not cleanup old SBOMs")
	} else {
		gitAccount.CommitAndPush(workingTree, "Deleted old SBOMs")
	}

	c.printNextExecution()
}

func deleteObsoleteFiles(workingTree string, ignoreDirs, processedSbomFiles []string, gitAccount git.GitAccount) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logrus.WithError(err).Errorf("An error occurred while processing %s", path)
			return nil
		}

		if info.IsDir() {
			dir := filepath.Base(path)
			for _, d := range ignoreDirs {
				if d == dir {
					return filepath.SkipDir
				}
			}
		}

		if info.Name() == "sbom.json" {
			found := false
			for _, f := range processedSbomFiles {
				if f == path {
					found = true
					break
				}
			}

			if !found {
				rel, _ := filepath.Rel(workingTree, path)
				gitAccount.RemoveFile(workingTree, rel)
				if err != nil {
					logrus.WithError(err).Errorf("File could not be deleted %s", path)
				} else {
					logrus.Debugf("Deleted old SBOM: %s", path)
				}
			}
		}

		return nil
	}
}
