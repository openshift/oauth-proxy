package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/csv"
	"io"
	"log"
	"os"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// Lookup passwords in a htpasswd file
// Passwords must be generated with -B for bcrypt or -s for SHA1.

type HtpasswdFile struct {
	Users       map[string]string
	usersRWLock sync.RWMutex
	watchDone   chan bool
	onUpdate    func()
}

func NewHtpasswdFromFile(path string) (*HtpasswdFile, error) {
	return newHtpasswdFromFileImpl(path, func() {})
}

func NewHtpasswd(file io.Reader) (*HtpasswdFile, error) {
	users, err := parseHtpasswd(file)
	if err != nil {
		return nil, err
	}
	h := &HtpasswdFile{Users: users}
	return h, nil
}

func newHtpasswdFromFileImpl(path string, onUpdate func()) (*HtpasswdFile, error) {
	r, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	h, err := NewHtpasswd(r)
	if err != nil {
		return nil, err
	}

	h.usersRWLock = sync.RWMutex{}
	h.watchDone = make(chan bool)
	h.onUpdate = onUpdate
	h.watch(path)
	return h, nil
}

func (h *HtpasswdFile) Validate(user string, password string) bool {
	users := h.loadUsers()
	realPassword, exists := users[user]
	if !exists {
		return false
	}
	shaPrefix := realPassword[:5]
	if shaPrefix == "{SHA}" {
		shaValue := realPassword[5:]
		d := sha1.New()
		d.Write([]byte(password))
		return shaValue == base64.StdEncoding.EncodeToString(d.Sum(nil))
	}

	bcryptPrefix := realPassword[:4]
	if bcryptPrefix == "$2a$" || bcryptPrefix == "$2x$" || bcryptPrefix == "$2y$" {
		return bcrypt.CompareHashAndPassword([]byte(realPassword), []byte(password)) == nil
	}

	log.Printf("Invalid htpasswd entry for %s. Must be a SHA or bcrypt entry.", user)
	return false
}

func (h *HtpasswdFile) storeUsers(users map[string]string) {
	h.usersRWLock.Lock()
	h.Users = users
	h.usersRWLock.Unlock()
}

func (h *HtpasswdFile) loadUsers() map[string]string {
	h.usersRWLock.RLock()
	defer h.usersRWLock.RUnlock()
	return h.Users
}

func (h *HtpasswdFile) watch(path string) {
	WatchForUpdates(path, h.watchDone, func() {
		r, err := os.Open(path)
		if err != nil {
			log.Printf("ERROR: couldn't open htpasswd file %s on reload: %s", path, err)
			return
		}
		defer r.Close()
		users, err := parseHtpasswd(r)
		if err != nil {
			log.Printf("ERROR: couldn't parse htpasswd file %s on reload: %s", path, err)
			return
		}
		h.storeUsers(users)
		if h.onUpdate != nil {
			h.onUpdate()
		}
		log.Printf("htpasswd file %s reloaded", path)
	})
}

func (h *HtpasswdFile) Close() {
	if h.watchDone != nil {
		close(h.watchDone)
	}
}

func parseHtpasswd(file io.Reader) (map[string]string, error) {
	csv_reader := csv.NewReader(file)
	csv_reader.Comma = ':'
	csv_reader.Comment = '#'
	csv_reader.TrimLeadingSpace = true

	records, err := csv_reader.ReadAll()
	if err != nil {
		return nil, err
	}
	users := make(map[string]string)
	for _, record := range records {
		users[record[0]] = record[1]
	}
	return users, nil
}
