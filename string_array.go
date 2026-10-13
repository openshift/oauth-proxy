package main

import (
	"flag"
	"strings"
)

var _ flag.Getter = StringArray{}

type StringArray struct {
	stringArray *[]string
}

func NewStringArray() *StringArray {
	return &StringArray{
		stringArray: &[]string{},
	}
}

func (a StringArray) Get() interface{} {
	if a.stringArray == nil {
		return nil
	}
	return *a.stringArray
}

func (a StringArray) Set(s string) error {
	*a.stringArray = append(*a.stringArray, s)
	return nil
}

func (a StringArray) String() string {
	if a.stringArray == nil {
		return ""
	}
	return strings.Join(*a.stringArray, ",")
}
