package models

type CVERecord struct {
	Cve              Cve            `json:"cve"`
	Configurations   Configurations `json:"configurations"`
	Impact           Impact         `json:"impact"`
	PublishedDate    string         `json:"publishedDate"`
	LastModifiedDate string         `json:"lastModifiedDate"`
}

type CVEDataMeta struct {
	ID       string `json:"ID"`
	ASSIGNER string `json:"ASSIGNER"`
}

type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type ProblemtypeData struct {
	Description []Description `json:"description"`
}

type Problemtype struct {
	ProblemtypeData []ProblemtypeData `json:"problemtype_data"`
}

type ReferenceData struct {
	URL       string        `json:"url"`
	Name      string        `json:"name"`
	Refsource string        `json:"refsource"`
	Tags      []interface{} `json:"tags"`
}

type References struct {
	ReferenceData []ReferenceData `json:"reference_data"`
}

type DescriptionData struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type DescriptionInfo struct {
	DescriptionData []DescriptionData `json:"description_data"`
}

type Cve struct {
	DataType        string          `json:"data_type"`
	DataFormat      string          `json:"data_format"`
	DataVersion     string          `json:"data_version"`
	CVEDataMeta     CVEDataMeta     `json:"CVE_data_meta"`
	Problemtype     Problemtype     `json:"problemtype"`
	References      References      `json:"references"`
	DescriptionInfo DescriptionInfo `json:"description"`
}

type CpeMatch struct {
	Vulnerable bool   `json:"vulnerable"`
	Cpe23URI   string `json:"cpe23Uri"`
}

type Nodes struct {
	Operator string     `json:"operator"`
	CpeMatch []CpeMatch `json:"cpe_match"`
}

type Configurations struct {
	CVEDataVersion string  `json:"CVE_data_version"`
	Nodes          []Nodes `json:"nodes"`
}

type CvssV2 struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	AccessVector          string  `json:"accessVector"`
	AccessComplexity      string  `json:"accessComplexity"`
	Authentication        string  `json:"authentication"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float64 `json:"baseScore"`
}

type BaseMetricV2 struct {
	CvssV2                  CvssV2  `json:"cvssV2"`
	Severity                string  `json:"severity"`
	ExploitabilityScore     float64 `json:"exploitabilityScore"`
	ImpactScore             float64 `json:"impactScore"`
	ObtainAllPrivilege      bool    `json:"obtainAllPrivilege"`
	ObtainUserPrivilege     bool    `json:"obtainUserPrivilege"`
	ObtainOtherPrivilege    bool    `json:"obtainOtherPrivilege"`
	UserInteractionRequired bool    `json:"userInteractionRequired"`
}

type Impact struct {
	BaseMetricV2 BaseMetricV2 `json:"baseMetricV2"`
}
