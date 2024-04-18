package main

import (
	"fmt"
	"os"
	"path"
	"sync"
	"testing"

	"github.com/bmizerany/assert"
)

func NewHtpasswdFromFileTest(path string, onUpdate func()) (*HtpasswdFile, error) {
	return newHtpasswdFromFileImpl(path, onUpdate)
}

func TestFileReload(t *testing.T) {
	htpasswdPath := path.Join(t.TempDir(), "htpasswd")
	if err := os.WriteFile(htpasswdPath, []byte("testuser:{SHA}PaVBVZkYqAjCQCu6UBL2xgsnZhw="), 0644); err != nil {
		fmt.Printf("failed to write htpasswd file: %s", err)
	}

	reloaded := make(chan struct{})
	htpasswd, err := NewHtpasswdFromFileTest(htpasswdPath, sync.OnceFunc(func() { close(reloaded) }))
	if err != nil {
		t.Fatalf("failed to create htpasswd: %s", err)
	}
	defer htpasswd.Close()

	valid := htpasswd.Validate("testuser", "asdf")
	assert.Equal(t, valid, true)

	if err := os.WriteFile(htpasswdPath, []byte("foo:{SHA}rjXz/gOeuoMRiEa7Get6eHtKkX0="), 0644); err != nil {
		fmt.Printf("failed to update htpasswd file: %s", err)
	}

	<-reloaded

	valid = htpasswd.Validate("testuser", "asdf")
	assert.Equal(t, valid, false)
	valid = htpasswd.Validate("foo", "ghjk")
	assert.Equal(t, valid, true)
}
