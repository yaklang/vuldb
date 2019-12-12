package dbm

import (
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"path"
	"vuldb/lib/fetcher"
)

var FixCVEDataFlags = []cli.Flag{
	cli.StringFlag{
		Name:  "dir,cve-dir",
		Usage: "CVE 数据目录",
		Value: "./data",
	},
	cli.StringFlag{
		Name:  "keyword,k",
		Usage: "需要修复的 cve 年份关键字 (2002-2020)",
	},
}

func FixCVEDataAction(c *cli.Context) error {
	k := c.String("k")
	if len(k) < 4 {
		return errors.Errorf("to wide keyword: %v", k)
	}
	result, err := fetcher.ReDownloadCVEDataByKeyword(c.String("dir"), k)
	if err != nil {
		return errors.Errorf("download failed: %s", err)
	}

	manager, err := NewDBManager()
	if err != nil {
		return errors.Errorf("create database manager failed: %s", err)
	}

	for fileName, _ := range result {
		fileName = path.Join(c.String("dir"), fileName)
		finished, err := loadCVEByFileName(fileName, manager)
		if err != nil {
			logrus.Error(err)
		}

		if finished {
			return errors.New("exit force")
		}

	}
	return nil
}
