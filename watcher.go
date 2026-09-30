//go:build go1.3 && !plan9 && !solaris
// +build go1.3,!plan9,!solaris

package main

import (
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

func WaitForReplacement(
	filename string, op fsnotify.Op,
	watcher *fsnotify.Watcher, done <-chan bool,
) bool {
	const sleepInterval = 50 * time.Millisecond

	// Avoid a race when fsnofity.Remove is preceded by fsnotify.Chmod.
	if op.Has(fsnotify.Chmod) {
		time.Sleep(sleepInterval)
	}
	for {
		if _, err := os.Stat(filename); err == nil {
			if err := watcher.Add(filename); err == nil {
				log.Printf("watching resumed for %s", filename)
				return true
			}
		}
		select {
		case <-done:
			return false
		case <-time.After(sleepInterval):
		}
	}
}

func WatchForUpdates(filename string, done <-chan bool, action func()) {
	filename = filepath.Clean(filename)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal("failed to create watcher for ", filename, ": ", err)
	}
	go func() {
		defer watcher.Close()
		for {
			select {
			case <-done:
				log.Printf("Shutting down watcher for: %s", filename)
				return
			case event := <-watcher.Events:
				// On Arch Linux, it appears Chmod events precede Remove events,
				// which causes a race between action() and the coming Remove event.
				// If the Remove wins, the action() (which calls
				// UserMap.LoadAuthenticatedEmailsFile()) crashes when the file
				// can't be opened.
				isFileBeingReplaced := event.Has(fsnotify.Remove) ||
					event.Has(fsnotify.Rename) ||
					event.Has(fsnotify.Chmod)
				if isFileBeingReplaced {
					log.Printf("watching interrupted on event: %s", event)
					if !WaitForReplacement(filename, event.Op, watcher, done) {
						log.Printf("Shutting down watcher for: %s", filename)
						return
					}
				}
				log.Printf("reloading after event: %s", event)
				action()
			case err := <-watcher.Errors:
				log.Printf("error watching %s: %s", filename, err)
			}
		}
	}()
	if err = watcher.Add(filename); err != nil {
		log.Fatal("failed to add ", filename, " to watcher: ", err)
	}
	log.Printf("watching %s for updates", filename)
}
