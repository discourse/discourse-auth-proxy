package main

import (
	"strings"
)

type StringSet []string

func NewStringSet(s string) StringSet {
	if len(s) == 0 {
		return []string{}
	}
	return strings.Split(s, ",")
}

func (ss StringSet) Contains(needle string) bool {
	for _, s := range ss {
		if s == needle {
			return true
		}
	}
	return false
}

func (ss StringSet) ContainsAny(needles StringSet) bool {
	for _, n := range needles {
		if ss.Contains(n) {
			return true
		}
	}
	return false
}
