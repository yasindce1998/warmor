package integrity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Database is the integrity allowlist mapping paths to known-good hashes.
type Database struct {
	Version  int                    `json:"version"`
	RootFS   string                 `json:"rootfs"`
	Binaries map[string]*BinaryHash `json:"binaries"`
}

// ScanRootFS walks the rootfs scanning all executable files and builds an integrity database.
func ScanRootFS(rootfs string) (*Database, error) {
	db := &Database{
		Version:  1,
		RootFS:   rootfs,
		Binaries: make(map[string]*BinaryHash),
	}

	execDirs := []string{"bin", "sbin", "usr/bin", "usr/sbin", "usr/local/bin", "usr/local/sbin"}

	for _, dir := range execDirs {
		fullDir := filepath.Join(rootfs, dir)
		if _, err := os.Stat(fullDir); os.IsNotExist(err) {
			continue
		}

		err := filepath.Walk(fullDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				return nil
			}
			if !isExecutable(info) {
				return nil
			}

			relPath, _ := filepath.Rel(rootfs, path)
			relPath = "/" + filepath.ToSlash(relPath)

			hash, err := HashFile(path)
			if err != nil {
				return nil
			}
			hash.Path = relPath
			db.Binaries[relPath] = hash
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walk %s: %w", fullDir, err)
		}
	}

	return db, nil
}

// ScanPaths scans specific file paths and builds an integrity database.
func ScanPaths(paths []string) (*Database, error) {
	db := &Database{
		Version:  1,
		Binaries: make(map[string]*BinaryHash),
	}

	for _, path := range paths {
		hash, err := HashFile(path)
		if err != nil {
			continue
		}
		db.Binaries[path] = hash
	}
	return db, nil
}

// LoadDatabase reads a JSON integrity database from file.
func LoadDatabase(path string) (*Database, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read database: %w", err)
	}
	var db Database
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("parse database: %w", err)
	}
	return &db, nil
}

// Save writes the database to a JSON file.
func (db *Database) Save(path string) error {
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal database: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// Verify checks a binary path against the database. Returns true if the hash matches.
func (db *Database) Verify(path string) (bool, error) {
	expected, ok := db.Binaries[path]
	if !ok {
		return false, nil
	}

	actual, err := HashFile(path)
	if err != nil {
		return false, err
	}

	return actual.SHA256 == expected.SHA256, nil
}

// LookupFastHash finds an entry by its fast hash and returns the expected SHA-256.
func (db *Database) LookupFastHash(pathHash uint32) *BinaryHash {
	for path, entry := range db.Binaries {
		if FastHashPath(path) == pathHash {
			return entry
		}
	}
	return nil
}

func isExecutable(info os.FileInfo) bool {
	if info.Mode()&0111 != 0 {
		return true
	}
	name := strings.ToLower(info.Name())
	if strings.HasSuffix(name, ".exe") || strings.HasSuffix(name, ".sh") {
		return true
	}
	// On Windows, execute bits aren't set. Treat extensionless files as executable
	// (matching Linux binary convention).
	if !strings.Contains(name, ".") {
		return true
	}
	return false
}
