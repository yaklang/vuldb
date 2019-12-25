package models

import (
	"fmt"
	"github.com/pkg/errors"
	"regexp"
	"strings"
)

type cpeStruct struct {
	// 7 for specific fields
	Part, Vendor, Product, Version, Update, Edition, Language string

	// for default
	Ext1, Ext2, Ext3, Ext4 string
}

func (c *cpeStruct) ProductCPE23() string {
	return fmt.Sprintf("cpe:2.3:%v:%v:%v", c.Part, c.Vendor, c.Product)
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

	result = append(result, genNextBuf(c.Version))
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

func (c *Configurations) ValidateCPE(cpes ...string) (bool, []string, error) {
	for _, n := range c.Nodes {
		if ok, cpes := n.ValidateCPEs(cpes...); ok {
			return true, cpes, nil
		}
	}

	return false, nil, nil
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

func (n *Nodes) ValidateCPEs(cpes ...string) (bool, []string) {
	type resource struct {
		r   *regexp.Regexp
		cpe string
	}
	var (
		res []*resource
		s   []string
	)

	for _, cpe := range cpes {
		ins, err := ParseCPEStringToStruct(cpe)
		if err != nil {
			s = append(s, cpe)
			continue
		}

		r, err := ins.Regexp()
		if err != nil {
			s = append(s, ins.CPE23String())
			continue
		}

		res = append(res, &resource{
			r:   r,
			cpe: cpe,
		})
	}

	var availableCPE []string
	result := n.Validate(func(t string) bool {
		for _, r := range res {
			if r.r.MatchString(t) {
				availableCPE = append(availableCPE, t)
				return true
			}
		}

		for _, sub := range s {
			if sub == t {
				availableCPE = append(availableCPE, sub)
				return true
			}
		}

		return false
	})

	return result, availableCPE
}

func (n *Nodes) ValidateRegexp(r *regexp.Regexp) bool {
	return n.Validate(r.MatchString)
}

func (n *Nodes) ValidateString(s string) bool {
	return n.Validate(func(t string) bool {
		return t == s
	})
}
