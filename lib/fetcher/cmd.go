package fetcher

import (
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var DownloadCVEFlags = []cli.Flag{}

func DownloadCVEAction(c *cli.Context) error {
	err := FetchJsonNvdCVEDataFeed()
	if err != nil {
		logrus.Errorf("download cve failed: %s", err)
		return err
	}

	return nil
}
