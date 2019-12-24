package dbm

import (
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var (
	QueryCPEToCVEFlags = []cli.Flag{
		cli.StringFlag{
			Name:  "cpe,c",
			Value: "CPE 样例",
		},
	}

	QueryCPEToCVEAction = func(c *cli.Context) error {
		cpe := c.String("cpe")

		m, err := NewDBManager()
		if err != nil {
			return errors.Errorf("build dbm failed: %v", err)
		}

		cves, err := m.QueryByCPE(cpe)
		if err != nil {
			return errors.Errorf("query cpe failed: %v", err)
		}

		for _, cve := range cves {
			logrus.Infof("found cve: %v", cve.CVE)
		}

		return nil
	}
)
