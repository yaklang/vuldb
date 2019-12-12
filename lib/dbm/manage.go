package dbm

import (
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

import (
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

type Manager struct {
	DB *gorm.DB
}

func NewDBManager() (*Manager, error) {
	m := &Manager{}

	params, err := GetPostgresParams()
	if err != nil {
		return nil, errors.Errorf("get postgres params failed: %s", err)
	}
	db, err := gorm.Open("postgres", params)
	if err != nil {
		return nil, errors.Errorf("open postgres db failed: %s", err)
	}
	m.DB = db

	db.AutoMigrate(&CVE{})

	return m, nil
}
