package util

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
)

func GetCertPool(paths []string, system_roots bool) (*x509.CertPool, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("Invalid empty list of Root CAs file paths")
	}
	var pool *x509.CertPool
	if system_roots {
		// ignore errors
		pool, _ = x509.SystemCertPool()
		if pool == nil {
			log.Printf("No system certificates found")
			pool = x509.NewCertPool()
		}
	} else {
		pool = x509.NewCertPool()
	}
	for _, path := range paths {
		data, err := ioutil.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("certificate authority file (%s) could not be read - %s", path, err)
		}
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("loading certificate authority (%s) failed", path)
		}
	}
	return pool, nil
}

// GetFilesMetadataHash returns base64-encoded hash of (size + name + modtime) of the file at path
func GetFilesMetadataHash(paths []string) (string, error) {
	hashData := make([]string, 0, len(paths))

	for _, path := range paths {
		meta, err := os.Stat(path)
		if err != nil {
			return "", fmt.Errorf("couldn't stat '%s': %v", path, err)
		}

		hashData = append(hashData, meta.Name()+strconv.FormatInt(meta.Size(), 10)+meta.ModTime().String())
	}

	// sort the strings so that the same paths in different order still generate the same hash
	sort.Strings(hashData)

	h := sha256.Sum256([]byte(strings.Join(hashData, "")))
	return base64.StdEncoding.EncodeToString(h[:]), nil
}
