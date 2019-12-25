package models

import (
	"fmt"
	"github.com/pkg/errors"
	"strings"
)

type VersionTreeNodeIf interface {
	GetChild(a byte) (*VersionCharNode, error)
	AddChild(a *VersionCharNode)
	GetChildren() []*VersionCharNode
	GetParent() VersionTreeNodeIf
	IsRoot() bool
}

type VersionTree struct {
	VersionTreeNodeIf

	//nodes []*VersionCharNode

	origin   []string
	children []*VersionCharNode
}

func (v *VersionTree) IsRoot() bool {
	return true
}

func (v *VersionTree) GetParent() VersionTreeNodeIf {
	return nil
}

func (v *VersionTree) GetChild(a byte) (*VersionCharNode, error) {
	for _, c := range v.children {
		if c.value == a {
			return c, nil
		}
	}
	return nil, errors.Errorf("no existed child for %#v", a)
}

func (v *VersionTree) AddChild(a *VersionCharNode) {
	v.children = append(v.children, a)
	a.parent = nil
}

func (v *VersionTree) GetChildren() []*VersionCharNode {
	return v.children[:]
}

type VersionCharNode struct {
	VersionTreeNodeIf
	value byte

	parent   VersionTreeNodeIf
	children []*VersionCharNode
}

func (v *VersionCharNode) GetChild(a byte) (*VersionCharNode, error) {
	for _, c := range v.children {
		if c.value == a {
			return c, nil
		}
	}
	return nil, errors.Errorf("no existed child for %#v", a)
}

func (v *VersionCharNode) AddChild(a *VersionCharNode) {
	v.children = append(v.children, a)
	a.parent = v
}

func (v *VersionCharNode) IsRoot() bool {
	return false
}

func (v *VersionCharNode) GetChildren() []*VersionCharNode {
	return v.children[:]
}

func (v *VersionCharNode) GetParent() VersionTreeNodeIf {
	return v.parent
}

func (v *VersionCharNode) IsLeaf() bool {
	return len(v.children) <= 0
}

func (v *VersionCharNode) NextString() string {
	if v.IsLeaf() {
		return fmt.Sprintf("%v", string(v.value))
	}

	var sub []string
	for _, c := range v.children {
		sub = append(sub, c.NextString())
	}

	if len(sub) > 1 {
		return fmt.Sprintf("%v[%v]", string(v.value), strings.Join(sub, "/"))
	} else {
		return fmt.Sprintf("%v%v", string(v.value), strings.Join(sub, "/"))
	}
}

func (v *VersionCharNode) PathString() string {
	var buf string

	var current VersionTreeNodeIf = v
	for {
		parent, ok := current.GetParent().(*VersionCharNode)
		if !ok {
			break
		}

		buf = string(parent.value) + buf
		current = parent
	}

	return buf
}

func (v *VersionCharNode) HaveLeaf() bool {
	for _, i := range v.children {
		if i.IsLeaf() {
			return true
		}
	}
	return false
}

func (v *VersionCharNode) Versions() []string {
	var haveLeaf []*VersionCharNode
	v.walk(func(n *VersionCharNode) {
		if n.HaveLeaf() {
			haveLeaf = append(haveLeaf, n)
		}
	})

	var s []string
	for _, y := range haveLeaf {
		s = append(s, fmt.Sprintf("%v%v", y.PathString(), y.NextString()))
	}
	return s
}

func (v *VersionCharNode) walk(h func(n *VersionCharNode)) {
	if v.IsLeaf() {
		h(v)
		return
	} else {
		for _, c := range v.children {
			h(c)
			c.walk(h)
		}
	}
}

func (v *VersionTree) init() {
	var parent VersionTreeNodeIf
	for _, ver := range v.origin {
		parent = v
		for _, c := range []byte(ver) {
			if node, err := parent.GetChild(c); err != nil {
				p := &VersionCharNode{
					value:  c,
					parent: parent,
				}
				parent.AddChild(p)
				//v.nodes = append(v.nodes, p)
				parent = p
			} else {
				parent = node
			}
		}
	}
}

func NewVersionTree(version ...string) *VersionTree {
	tree := &VersionTree{
		origin: version,
	}
	tree.init()

	return tree
}

func (v *VersionTree) String() string {
	var s []string
	for _, c := range v.children {
		if c.IsLeaf() {
			s = append(s, c.PathString()+string(c.value))
		} else {
			s = append(s, c.Versions()...)
		}
	}

	return strings.Join(s, "/")
}
