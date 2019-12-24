package dbm

import (
	"encoding/json"
	"fmt"
	"github.com/jinzhu/gorm"
	"github.com/jinzhu/gorm/dialects/postgres"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"time"
	"vuldb/lib/models"
	"vuldb/utils"
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

func (c *CVE) ValidateCPE(cpe string) (bool, error) {
	data, err := c.CPEConfigurations.MarshalJSON()
	if err != nil {
		return false, errors.Errorf("%v marshal json failed: %v", c.CVE, err)
	}

	var config models.Configurations
	err = json.Unmarshal(data, &config)
	if err != nil {
		return false, errors.Errorf("%v convert to configuration failed: %v", c.CVE, err)
	}

	if ok, err := config.ValidateCPE(cpe); ok {
		return true, nil
	} else {
		if utils.InDebugMode() {
			data, e := json.MarshalIndent(config, c.CVE, "    ")
			if e != nil {
				logrus.Error(e)
			} else {
				logrus.Info(string(data))
			}
		}
		return false, err
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

func (m *Manager) QueryByCPE(cpe string) ([]*CVE, error) {
	db := m.DB

	s, err := models.ParseCPEStringToStruct(cpe)
	if err != nil {
		return nil, errors.Errorf("parse cpe failed: %v", err)
	}

	var cves []*CVE
	if db := db.Where(
		"cpe_configurations->>'nodes' LIKE ?",
		fmt.Sprintf("%%%v%%", s.CPE23String()),
	).Find(&cves); db.Error != nil {
		return nil, errors.Errorf("query cve by cpe failed: %v", db.Error)
	}

	var results []*CVE
	for _, cve := range cves {
		if ok, err := cve.ValidateCPE(cpe); ok {
			results = append(results, cve)
		} else {
			if err != nil {
				logrus.Errorf("CVE: %v failed: %v", cve.CVE, err)
			}
		}
	}

	logrus.Infof("found raw cve: %v valid cve: %v", len(cves), len(results))

	return results, nil
}
