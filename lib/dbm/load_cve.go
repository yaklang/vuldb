package dbm

import (
	"encoding/json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"io/ioutil"
	"path"
	"vuldb/lib/fetcher"
	"vuldb/lib/models"
)

var LoadCVEFlags = []cli.Flag{
	cli.StringFlag{
		Name:  "cve-dir,dir",
		Usage: "CVE 原始数据(JSON) 的文件夹",
		Value: "./data",
	},
}

func LoadCVEAction(c *cli.Context) error {
	manager, err := NewDBManager()
	if err != nil {
		return errors.Errorf("get db manager failed: %s", err)
	}

	baseDir := c.String("dir")

	for fileName, _ := range fetcher.CveDataFeed {
		fileName = path.Join(baseDir, fileName)

		finished, err := loadCVEByFileName(fileName, manager)
		if err != nil {
			logrus.Errorf("load %v failed: %s", fileName, err)
		}

		if finished {
			return errors.Errorf("finished force")
		}
	}
	return nil
}

func loadCVEByFileName(fileName string, manager *Manager) (shouldExit bool, err error) {
	logrus.Infof("preparing to handling: %v", fileName)
	body, err := ioutil.ReadFile(fileName)
	if err != nil {
		return false, errors.Errorf("load %s failed: %s", fileName, err)
	}

	var cveFile models.CVEYearFile
	err = json.Unmarshal(body, &cveFile)
	if err != nil {
		return false, errors.Errorf("unmarshal cve file failed: %s", err)
	}

	logrus.Infof("read file finished, start to loading %v 's cve records", fileName)
	var failedCount int
	for _, record := range cveFile.CVERecords {
		err := manager.SaveCVERecord(&record)
		if err != nil {
			failedCount += 1
			logrus.Errorf("save cve record failed: %s", err)
		}

		if failedCount > 30 {
			return true, errors.New("failed too many times")
		}
	}

	logrus.Info("handle finished for ", fileName)
	return false, nil
}
