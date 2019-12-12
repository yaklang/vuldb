package main

import (
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"os"
	"vuldb/lib/fetcher"
)

func main() {
	app := cli.NewApp()

	app.Commands = []cli.Command{
		{
			Name: "download-cve",
			Usage: "下载 CVE 数据",
			Flags: fetcher.DownloadCVEFlags,
			Action: fetcher.DownloadCVEAction,
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		logrus.Errorf("cmd failed: %s", err)
		return
	}
}
