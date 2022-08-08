package fetcher

import (
	"compress/gzip"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
	"vuldb/utils"
)

var CveDataFeed = map[string]string{
	"CVE-2002.json": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2002.json.gz",
	"CVE-2003.json": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2003.json.gz",
	"CVE-2004.json": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2004.json.gz",
	"CVE-2005.json": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2005.json.gz",
	"CVE-2006.json": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2006.json.gz",
	"CVE-2007.json": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2007.json.gz",
	"CVE-2008.json": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2008.json.gz",
	"CVE-2009.json": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2009.json.gz",
	"CVE-2010.json": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2010.json.gz",
	"CVE-2011.json": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2011.json.gz",
	"CVE-2012.json": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2012.json.gz",
	"CVE-2013.json": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2013.json.gz",
	"CVE-2014.json": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2014.json.gz",
	"CVE-2015.json": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2015.json.gz",
	"CVE-2016.json": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2016.json.gz",
	"CVE-2017.json": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2017.json.gz",
	"CVE-2018.json": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2018.json.gz",
	"CVE-2019.json": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2019.json.gz",
	"CVE-2020.json": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2020.json.gz",
	"CVE-2021.json": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2021.json.gz",
	"CVE-2022.json": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2022.json.gz",
}

func FetchJsonNvdCVEDataFeed(dir string) error {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	swg := utils.NewSizedWaitGroup(10)
	for fileName, url := range CveDataFeed {
		swg.Add()
		url := url
		fileName := fileName
		go func() {
			defer swg.Done()

			fileName := path.Join(dir, fileName)
			err := loadGzToFile(client, url, fileName)
			if err != nil {
				logrus.Error(err)
			}
		}()
	}

	swg.Wait()
	return nil
}

func ReDownloadCVEDataByKeyword(dir, kw string) (map[string]string, error) {
	result := map[string]string{}
	for name, u := range CveDataFeed {
		if strings.Contains(name, kw) {
			result[name] = u
		}
	}

	swg := utils.NewSizedWaitGroup(5)
	for name, u := range result {
		fileName := path.Join(dir, name)
		swg.Add()
		go func() {
			defer swg.Done()
			err := loadGzToFile(http.DefaultClient, u, fileName)
			if err != nil {
				logrus.Error(err)
			}
		}()
	}
	swg.Wait()

	return result, nil
}

func loadGzToFile(client *http.Client, url string, fileName string) error {
	logrus.Infof("downloading %s", url)
	resp, err := client.Get(url)
	if err != nil {
		return errors.Errorf("download %s failed: %s", url, err)
	}

	rawData, err := gzip.NewReader(resp.Body)
	if err != nil {
		return errors.Errorf("gzip decompress failed: %s", err)
	}

	dstFile, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return errors.Errorf("open file failed: %s", err)
	}

	_, err = io.Copy(dstFile, rawData)
	if err != nil {
		return errors.Errorf("copy to local failed: %s", err)
	}
	return nil
}
