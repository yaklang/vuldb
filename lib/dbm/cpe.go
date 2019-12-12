package dbm

import "github.com/lib/pq"

type CPE struct {
	CPE  string         `gorm:"unique_index,primary_key"`
	CVEs pq.StringArray `gorm:"type:varchar(4096)[],column:cves"`
}
