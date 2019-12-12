package fetcher

import (
	"compress/gzip"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
	"os"
	"path"
	"time"
	"vuldb/utils"
)

var cveDataUrls = map[string]string{
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
}

func FetchJsonNvdCVEDataFeed() error {
	client := http.Client{
		Timeout: 30 * time.Second,
	}

	swg := utils.NewSizedWaitGroup(10)
	for fileName, url := range cveDataUrls {
		swg.Add()
		url := url
		fileName := fileName
		go func() {
			defer swg.Done()

			logrus.Infof("downloading %s", url)
			resp, err := client.Get(url)
			if err != nil {
				logrus.Errorf("download %s failed: %s", url, err)
				return
			}

			rawData, err := gzip.NewReader(resp.Body)
			if err != nil {
				logrus.Errorf("gzip decompress failed: %s", err)
				return
			}

			fileName := path.Join("./data", fileName)
			dstFile, err := os.OpenFile(fileName, os.O_WRONLY | os.O_CREATE, 0666)
			if err != nil {
				logrus.Errorf("open file failed: %s", err)
				return
			}

			logrus.Info("downloaded")

			_, err = io.Copy(dstFile, rawData)
			if err != nil {
				logrus.Errorf("copy to local failed: %s", err)
				return
			}
		}()
	}

	swg.Wait()
	return nil
}
