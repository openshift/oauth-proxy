package main

import (
	"flag"
	"testing"

	"github.com/bmizerany/assert"
)

func TestStringArray(t *testing.T) {
	sa := NewStringArray()
	assert.Equal(t, "", sa.String())
	err := sa.Set("foo")
	if err != nil {
		t.Errorf("unexpected error %v", err)
	}
	assert.Equal(t, "foo", sa.String())
	err = sa.Set("bar")
	if err != nil {
		t.Errorf("unexpected error %v", err)
	}
	assert.Equal(t, "foo,bar", sa.String())
}

func TestStringArrayInFlagSet(t *testing.T) {
	sa := NewStringArray()

	// flagset tries to grab an empty interface of each flag and invokes
	// their .String() method to check whether they are empty
	flagSet := flag.NewFlagSet("cool flagset", flag.ExitOnError)
	flagSet.Var(sa, "favourite colours", "colourful storm")
	flagSet.PrintDefaults()
}
