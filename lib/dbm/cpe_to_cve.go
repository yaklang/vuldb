package dbm

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var (
	QueryCPEToCVEFlags = []cli.Flag{
		cli.StringSliceFlag{
			Name:  "cpe,c",
			Usage: "需要对哪些 cpe 进行搜索？",
		},
		cli.StringFlag{
			Name:  "part,p",
			Usage: "cpe part filter ('a' for must-have-a, '*' for ignore, a/h/o for filter) ",
		},
	}

	QueryCPEToCVEAction = func(c *cli.Context) error {
		cpes := c.StringSlice("cpe")

		m, err := NewDBManager()
		if err != nil {
			return errors.Errorf("build dbm failed: %v", err)
		}

		verified, unverified, err := m.QueryByCPEsWithOptions(CPEFilter(c.String("part")), cpes...)
		if err != nil {
			return errors.Errorf("query cpe failed: %v", err)
		}

		for _, cve := range verified {
			logrus.Infof("found cve: %20s cpe: %v", cve.CVE.CVE, cve.AvailableCPEs)
			s, err := cve.CVE.CPEHumanReadableString()
			if err != nil {
				continue
			}
			logrus.Infof("%v vuln configurations: \n\n%v\n\n", cve.CVE.CVE, s)
		}

		fmt.Println()

		for _, cve := range unverified {
			logrus.Infof("unverified cve: %20s cpe: %v", cve.CVE.CVE, cve.AvailableCPEs)
			s, err := cve.CVE.CPEHumanReadableString()
			if err != nil {
				continue
			}
			logrus.Infof("%v vuln configurations: \n\n%v\n\n", cve.CVE.CVE, s)
		}

		return nil
	}
)
