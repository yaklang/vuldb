package main

import (
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"os"
	"vuldb/lib/dbm"
	"vuldb/lib/fetcher"
)

func main() {
	logrus.Info("start to checking postgres in docker")
	err := dbm.StartPostgres()
	if err != nil {
		logrus.Errorf("start postgres database in docker failed: %s", err)
		return
	}

	app := cli.NewApp()

	app.Commands = []cli.Command{
		{
			Name:   "download-cve",
			Usage:  "下载 CVE 数据",
			Flags:  fetcher.DownloadCVEFlags,
			Action: fetcher.DownloadCVEAction,
		},
		{
			Name:   "save-to-db",
			Usage:  "把数据装载进数据库",
			Flags:  dbm.LoadCVEFlags,
			Action: dbm.LoadCVEAction,
		},
		{
			Name:   "fix-cve",
			Usage:  "修复丢失的 CVE 数据(通过年份关键字)",
			Flags:  dbm.FixCVEDataFlags,
			Action: dbm.FixCVEDataAction,
		},
		{
			Name:   "download-exploit",
			Usage:  "下载 ExploitDB 中的数据",
			Flags:  fetcher.DownloadExploitDBFlags,
			Action: fetcher.DownloadExploitDBAction,
		},
		{
			Name:   "cpe2cve",
			Usage:  "通过 CPE 查询 CVE",
			Flags:  dbm.QueryCPEToCVEFlags,
			Action: dbm.QueryCPEToCVEAction,
		},
	}

	err = app.Run(os.Args)
	if err != nil {
		logrus.Errorf("cmd failed: %s", err)
		return
	}
}
