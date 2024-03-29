package models

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCPEStruct(t *testing.T) {
	cpe := &cpeStruct{
		Vendor:   "nginx",
		Product:  "nginx",
		Version:  "1.4",
		Language: "en",
	}

	re, err := cpe.Regexp()
	if err != nil {
		logrus.Error(err)
		return
	}
	fmt.Printf("%v\n", re.String())

	assert.True(t, re.MatchString("cpe:2.3:a:nginx:nginx:1.4:::en:"))
	assert.True(t, re.MatchString(cpe.CPE23String()))
}
