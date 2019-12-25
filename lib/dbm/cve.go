package dbm

import (
	"encoding/json"
	"fmt"
	"github.com/jinzhu/gorm"
	"github.com/jinzhu/gorm/dialects/postgres"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"strings"
	"time"
	"vuldb/lib/models"
	"vuldb/utils"
)

type CPEFilter string

const (
	CPE_Filter_Default          CPEFilter = ""
	CPE_Filter_MustHaveCPEPartA           = CPE_Filter_Default
	CPE_Filter_AllTypeCPEPart   CPEFilter = "*"
	CPE_Filter_OnlyCPEPartA     CPEFilter = "a"
	CPE_Filter_OnlyCPEPartH     CPEFilter = "h"
	CPE_Filter_OnlyCPEPartO     CPEFilter = "o"
)

type CVE struct {
	gorm.Model

	CVE             string `gorm:"primary_key"`
	CWE             string
	ProblemType     postgres.Jsonb
	References      postgres.Jsonb
	DescriptionMain string
	Descriptions    postgres.Jsonb

	CPEConfigurations postgres.Jsonb

	CVSSVersion      string
	CVSSVectorString string

	// 攻击路径
	AccessVector string
	// 攻击复杂度
	AccessComplexity string
	// 需要认证
	Authentication string
	// 机密性影响（泄密）
	ConfidentialityImpact string
	// 完整性影响（破坏程度）
	IntegrityImpact string
	// 可用性影响（导致服务不可用）
	AvailabilityImpact string
	// 基础评分
	BaseCVSSv2Score float64

	// 严重等级
	Severity string
	// 漏洞利用评分
	ExploitabilityScore float64
	// 漏洞影响评分
	ImpactScore float64

	// 可获取所有权限
	ObtainAllPrivilege bool
	// 可获取用户权限
	ObtainUserPrivilege bool
	// 可获取其他权限
	ObtainOtherPrivilege bool

	// 是否需要用户交互
	UserInteractionRequired bool

	PublishedDate    time.Time
	LastModifiedData time.Time
}

type CVEResult struct {
	CVE           *CVE
	AvailableCPEs []string
}

func (c *CVE) FitCPEs(option CPEFilter, cpes ...string) (*CVEResult, bool) {
	result := &CVEResult{
		CVE:           c,
		AvailableCPEs: cpes,
	}
	switch option {
	case CPE_Filter_MustHaveCPEPartA:
		return result, c.HaveCPEPartA(cpes...)
	case CPE_Filter_AllTypeCPEPart:
		return result, true
	case CPE_Filter_OnlyCPEPartA:
		return result, c.HaveCPEPartA(cpes...) && !c.HaveCPEPartH(cpes...) && !c.HaveCPEPartO(cpes...)
	case CPE_Filter_OnlyCPEPartH:
		return result, !c.HaveCPEPartA(cpes...) && c.HaveCPEPartH(cpes...) && !c.HaveCPEPartO(cpes...)
	case CPE_Filter_OnlyCPEPartO:
		return result, !c.HaveCPEPartA(cpes...) && !c.HaveCPEPartH(cpes...) && c.HaveCPEPartO(cpes...)
	default:
		return result, (c.HaveCPEPartA(cpes...) && strings.Contains(string(option), "a")) ||
			(c.HaveCPEPartO(cpes...) && strings.Contains(string(option), "o")) ||
			(c.HaveCPEPartH(cpes...) && strings.Contains(string(option), "h"))
	}
}

func cpeHavePart(s string, flag string) bool {
	sub1, sub2 := fmt.Sprintf("cpe:2.3:%v", flag), fmt.Sprintf("cpe:/%v", flag)
	return strings.HasPrefix(s, sub1) || strings.HasPrefix(s, sub2)
}

func (c *CVE) HaveCPEPartA(cpes ...string) bool {
	return c.HaveCPEPart("a", cpes...)
}

func (c *CVE) HaveCPEPartH(cpes ...string) bool {
	return c.HaveCPEPart("h", cpes...)
}

func (c *CVE) HaveCPEPartO(cpes ...string) bool {
	return c.HaveCPEPart("o", cpes...)
}

func (c *CVE) HaveCPEPart(flag string, cpes ...string) bool {
	for _, c := range cpes {
		if cpeHavePart(c, flag) {
			return true
		}
	}
	return false
}

func (c *CVE) CPEHumanReadableString() (string, error) {
	data, err := c.CPEConfigurations.MarshalJSON()
	if err != nil {
		return "", errors.Errorf("%v marshal json failed: %v", c.CVE, err)
	}

	var config models.Configurations
	err = json.Unmarshal(data, &config)
	if err != nil {
		return "", errors.Errorf("%v convert to configuration failed: %v", c.CVE, err)
	}

	return config.ToHumanReadableString(), nil
}

func (c *CVE) ValidateCPE(cpes ...string) (ok bool, availableCPE []string, _ error) {
	data, err := c.CPEConfigurations.MarshalJSON()
	if err != nil {
		return false, nil, errors.Errorf("%v marshal json failed: %v", c.CVE, err)
	}

	var config models.Configurations
	err = json.Unmarshal(data, &config)
	if err != nil {
		return false, nil, errors.Errorf("%v convert to configuration failed: %v", c.CVE, err)
	}

	if ok, availableCPE, err := config.ValidateCPE(cpes...); ok {
		return true, availableCPE, nil
	} else {
		if utils.InDebugMode() {
			data, e := json.MarshalIndent(config, c.CVE, "    ")
			if e != nil {
				logrus.Error(e)
			} else {
				logrus.Info(string(data))
			}
		}
		return false, nil, err
	}
}

func (m *Manager) SaveCVERecord(r *models.CVERecord) error {
	problemType, err := r.ProblemTypeToJSONB()
	if err != nil {
		logrus.Errorf("save cve record failed: %s", err)
	}

	references, err := r.ReferencesToJSONB()
	if err != nil {
		logrus.Errorf("record references failed: %s", err)
	}

	descs, err := r.DescriptionsToJSONB()
	if err != nil {
		logrus.Errorf("descriptions failed: %s", err)
	}

	configs, err := r.CPEConfigurationsToJSONB()
	if err != nil {
		logrus.Errorf("configuration failed: %s", err)
	}

	matrix := r.Impact.BaseMetricV2
	cvss := matrix.CvssV2

	pubdate := r.GetPublishedDate()
	if pubdate.IsZero() {
		logrus.Warnf("invalid data for %v", r.PublishedDate)
	}

	lastModifiedDate := r.GetLastModifiedDate()
	if lastModifiedDate.IsZero() {
		logrus.Warnf("invalid data for %v", r.LastModifiedDate)
	}

	cve := &CVE{
		CVE:                     r.CVEId(),
		CWE:                     r.CWE(),
		ProblemType:             problemType,
		References:              references,
		DescriptionMain:         r.DescriptionMain(),
		Descriptions:            descs,
		CPEConfigurations:       configs,
		CVSSVersion:             cvss.Version,
		CVSSVectorString:        cvss.VectorString,
		AccessVector:            cvss.AccessVector,
		AccessComplexity:        cvss.AccessComplexity,
		Authentication:          cvss.Authentication,
		ConfidentialityImpact:   cvss.ConfidentialityImpact,
		IntegrityImpact:         cvss.IntegrityImpact,
		AvailabilityImpact:      cvss.AvailabilityImpact,
		BaseCVSSv2Score:         cvss.BaseScore,
		Severity:                matrix.Severity,
		ExploitabilityScore:     matrix.ExploitabilityScore,
		ImpactScore:             matrix.ImpactScore,
		ObtainAllPrivilege:      matrix.ObtainAllPrivilege,
		ObtainUserPrivilege:     matrix.ObtainUserPrivilege,
		ObtainOtherPrivilege:    matrix.ObtainOtherPrivilege,
		UserInteractionRequired: matrix.UserInteractionRequired,
		PublishedDate:           pubdate,
		LastModifiedData:        lastModifiedDate,
	}

	if db := m.DB.Save(cve); db.Error != nil {
		return errors.Errorf("save cve %s failed: %s", cve.CVE, err)
	}
	return nil
}

func (m *Manager) QueryByCPEs(cpes ...string) (known, unverified []*CVEResult, _ error) {
	return m.QueryByCPEsWithOptions(CPE_Filter_Default, cpes...)
}

func (m *Manager) QueryByCPEsWithOptions(option CPEFilter, cpes ...string) (known, unverified []*CVEResult, _ error) {
	db := m.DB

	var allCves []*CVE

	for _, cpe := range cpes {
		s, err := models.ParseCPEStringToStruct(cpe)
		if err != nil {
			return nil, nil, errors.Errorf("parse cpe failed: %v", err)
		}

		var cves []*CVE
		if db := db.Where(
			"cpe_configurations->>'nodes' LIKE ?",
			fmt.Sprintf("%%%v%%", s.CPE23String()),
		).Find(&cves); db.Error != nil {
			return nil, nil, errors.Errorf("query cve by cpe failed: %v", db.Error)
		}

		allCves = append(allCves, cves...)
	}

	var (
		positiveResults []*CVEResult
		negativeResults []*CVEResult
	)
	for _, cve := range allCves {
		if ok, availableCPE, err := cve.ValidateCPE(cpes...); ok {
			if r, available := cve.FitCPEs(option, availableCPE...); available {
				positiveResults = append(positiveResults, r)
			}
		} else {
			if err != nil {
				logrus.Errorf("CVE: %v failed: %v", cve.CVE, err)
			}

			if r, available := cve.FitCPEs(option, availableCPE...); available {
				negativeResults = append(negativeResults, r)
			}
		}
	}

	logrus.Infof("found raw cve: %v valid cve: %v", len(allCves), len(positiveResults))

	return positiveResults, negativeResults, nil
}
