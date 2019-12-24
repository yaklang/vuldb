package models

import (
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"regexp"
	"strings"
)

type cpeStruct struct {
	// 7 for specific fields
	Part, Vendor, Product, Version, Update, Edition, Language string

	// for default
	Ext1, Ext2, Ext3, Ext4 string
}

func newCPEStruct(a []string) (*cpeStruct, error) {
	if len(a) < 11 {
		return nil, errors.Errorf("invalid cpe content array: %v", a)
	}
	return &cpeStruct{
		Part:     a[0],
		Vendor:   a[1],
		Product:  a[2],
		Version:  a[3],
		Update:   a[4],
		Edition:  a[5],
		Language: a[6],
		Ext1:     a[7],
		Ext2:     a[8],
		Ext3:     a[9],
		Ext4:     a[10],
	}, nil
}

func (c *cpeStruct) CPE23String() string {
	orStr := func(s string, defaultValue string) string {
		if s == "" {
			return defaultValue
		}
		return s
	}

	orStar := func(s string) string {
		return orStr(s, "*")
	}

	var result []string

	result = append(result, orStr(c.Part, "a"))
	result = append(result, orStar(c.Vendor))
	result = append(result, orStar(c.Product))
	result = append(result, orStar(c.Version))
	result = append(result, orStar(c.Update))
	result = append(result, orStar(c.Edition))
	result = append(result, orStar(c.Language))
	result = append(result, orStar(c.Ext1))
	result = append(result, orStar(c.Ext2))
	result = append(result, orStar(c.Ext3))
	result = append(result, orStar(c.Ext4))

	return "cpe:2.3:" + strings.Join(result, ":")
}

func (c *cpeStruct) Regexp() (*regexp.Regexp, error) {
	data := func(s string) string {
		return regexp.QuoteMeta(s)
	}

	orStr := func(s string, defaultValue string) string {
		if strings.TrimSpace(s) == "" {
			return defaultValue
		}
		return data(s)
	}

	var result []string

	block := "([^:]+|*)"
	result = append(result, orStr(c.Part, "a"))

	orAny := func(s string) string {
		return orStr(s, block)
	}

	result = append(result, orAny(c.Vendor))
	result = append(result, orAny(c.Product))
	result = append(result, orAny(c.Version))

	buf := `(cpe:\d\.\d:|cpe:\/)` + strings.Join(result, ":")

	// available options
	orAnyOrNull := func(s string) (_ string, isEmpty bool) {
		if strings.TrimSpace(s) == "" {
			return `(\*|([^:]+))?`, true
		}
		return data(s), false
	}

	genNextBuf := func(c string) string {
		if buffer, ok := orAnyOrNull(c); ok {
			return ":?" + buffer
		} else {
			return ":" + buffer + ":"
		}
	}

	result = []string{}

	result = append(result, genNextBuf(c.Update))
	result = append(result, genNextBuf(c.Edition))
	result = append(result, genNextBuf(c.Language))
	result = append(result, genNextBuf(c.Ext1))
	result = append(result, genNextBuf(c.Ext2))
	result = append(result, genNextBuf(c.Ext3))
	result = append(result, genNextBuf(c.Ext4))

	_ = buf
	raw := buf + ":?" + strings.Join(result, ":?")
	return regexp.Compile(raw)
}

func ParseCPEStringToStruct(cpe string) (*cpeStruct, error) {
	if strings.HasPrefix(cpe, "cpe:/") {
		cpe = "cpe:2.3:" + cpe[5:]
	} else if strings.HasPrefix(cpe, "cpe:2.3:") {
		// valid
	} else {
		return nil, errors.Errorf("invalid cpe format: %v", cpe)
	}

	// remove cpe:2.3: header
	rets := strings.Split(cpe[8:], ":")
	if len(rets) < 3 {
		return nil, errors.Errorf("cpe content is invalid: %v, the content is short", cpe)
	} else if len(rets) > 11 {
		return nil, errors.Errorf("cpe content is invalid: %v, the content is too long", cpe)
	}

	var cpeArray = make([]string, 11)
	copy(cpeArray, rets)

	cpeIns, err := newCPEStruct(cpeArray)
	if err != nil {
		return nil, errors.Errorf("build cpe struct failed: %v", err)
	}

	return cpeIns, nil
}

func (c *Configurations) ValidateCPE(cpe string) (bool, error) {
	cpeIns, err := ParseCPEStringToStruct(cpe)
	if err != nil {
		return false, err
	}

	var (
		r *regexp.Regexp
		s string
	)
	r, err = cpeIns.Regexp()
	if err != nil {
		logrus.Errorf("build cpe regexp failed: %v", err)
		s = cpeIns.CPE23String()
	}

	if r == nil && s == "" {
		return false, errors.Errorf("parse cpe regexp/string failed: %v", cpe)
	}

	for _, n := range c.Nodes {
		if r != nil {
			if n.ValidateRegexp(r) {
				return true, nil
			}
		}

		if s != "" {
			if n.ValidateString(s) {
				return true, nil
			}
		}
	}

	return false, nil
}

func (n *Nodes) Validate(h func(t string) bool) bool {
	switch n.Operator {
	case "AND", "And", "and":
		for _, subNode := range n.Children {
			if !subNode.Validate(h) {
				return false
			}
		}

		if len(n.Children) > 0 {
			return true
		} else {
			return false
		}
	case "OR", "or", "Or":
		for _, m := range n.CpeMatch {
			if m.Vulnerable && h(m.Cpe23URI) {
				return true
			}
		}
	}
	return false
}

func (n *Nodes) ValidateRegexp(r *regexp.Regexp) bool {
	return n.Validate(r.MatchString)
}

func (n *Nodes) ValidateString(s string) bool {
	return n.Validate(func(t string) bool {
		return t == s
	})
}
