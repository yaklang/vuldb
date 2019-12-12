package fetcher

import (
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var DownloadCVEFlags = []cli.Flag{
	cli.StringFlag{
		Name:  "dir,cve-dir",
		Usage: "存储 CVE 原始数据的文件夹",
		Value: "./data",
	},
}

func DownloadCVEAction(c *cli.Context) error {

	err := FetchJsonNvdCVEDataFeed(c.String("dir"))
	if err != nil {
		logrus.Errorf("download cve failed: %s", err)
		return err
	}

	return nil
}
