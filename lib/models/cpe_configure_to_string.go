package models

import (
	"fmt"
	"strings"
)

func (c *Configurations) ToHumanReadableString() string {
	var r []string
	for _, n := range c.Nodes {
		r = append(r, n.ToHumanReadableString())
	}

	var results []string
	if len(r) > 1 {
		for _, res := range r {
			results = append(results, fmt.Sprintf("(%v)", res))
		}
	} else {
		results = r[:]
	}

	return strings.Join(results, " or ")
}

type cpeCluster struct {
	c        *cpeStruct
	versions []string
}

func (c *cpeCluster) CompactVersions() string {
	tree := NewVersionTree(c.versions...)
	return tree.String()
}

func (n *Nodes) ToHumanReadableString() string {
	switch n.Operator {
	case "AND", "and", "And":
		var ss []string
		for _, c := range n.Children {
			s := c.ToHumanReadableString()
			ss = append(ss, fmt.Sprintf("(%v)", s))
		}
		return strings.Join(ss, " and ")
	case "OR", "Or", "or":

		var table = make(map[string]*cpeCluster)
		for _, m := range n.CpeMatch {
			if !m.Vulnerable {
				continue
			}

			ins, err := ParseCPEStringToStruct(m.Cpe23URI)
			if err != nil {
				continue
			}

			cluster, ok := table[ins.ProductCPE23()]
			if !ok {
				cluster = &cpeCluster{
					c: &cpeStruct{
						Part:    ins.Part,
						Vendor:  ins.Vendor,
						Product: ins.Product,
					},
				}
				table[ins.ProductCPE23()] = cluster
			}

			cluster.versions = append(cluster.versions, ins.Version)
		}

		var s []string
		for product, clusterCPE := range table {
			s = append(s, fmt.Sprintf("%v:%v", product, clusterCPE.CompactVersions()))
		}

		var ret []string
		if len(s) > 1 {
			ret = append(ret, fmt.Sprintf("(%v)", s))
		}
		return strings.Join(ret, " or ")
	}
	return "unknown"
}
