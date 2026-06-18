package sbompolicy

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	posixpath "path"
	"strings"
)

var pathDirs = map[string]bool{
	"/usr/bin":       true,
	"/usr/sbin":      true,
	"/bin":           true,
	"/sbin":          true,
	"/usr/local/bin": true,
}

var libDirs = []string{
	"/usr/lib",
	"/lib",
	"/usr/local/lib",
}

func Resolve(packages []Package, opts ResolveOptions) ([]ResolvedFile, error) {
	if opts.RootFS == "" {
		opts.RootFS = "/"
	}
	if opts.Level == "" {
		opts.Level = "binary"
	}

	distro, err := detectDistro(opts.RootFS)
	if err != nil {
		return nil, err
	}

	pkgFiles, err := loadPackageDB(distro, opts.RootFS)
	if err != nil {
		return nil, err
	}

	var resolved []ResolvedFile
	for _, pkg := range packages {
		files, ok := pkgFiles[pkg.Name]
		if !ok {
			continue
		}
		for _, f := range files {
			ft := classifyFile(f)
			if !includeFile(ft, opts.Level) {
				continue
			}
			resolved = append(resolved, ResolvedFile{
				Path:        f,
				PackageName: pkg.Name,
				FileType:    ft,
			})
		}
	}

	return resolved, nil
}

func detectDistro(rootfs string) (string, error) {
	if fileExists(filepath.Join(rootfs, "lib/apk/db/installed")) {
		return "apk", nil
	}
	if dirExists(filepath.Join(rootfs, "var/lib/dpkg/info")) {
		return "deb", nil
	}
	if dirExists(filepath.Join(rootfs, "var/lib/rpm")) || dirExists(filepath.Join(rootfs, "usr/lib/sysimage/rpm")) {
		return "rpm", nil
	}
	return "", fmt.Errorf("cannot detect package manager in rootfs %q: no APK/DEB/RPM database found", rootfs)
}

func loadPackageDB(distro, rootfs string) (map[string][]string, error) {
	switch distro {
	case "apk":
		return loadAPK(rootfs)
	case "deb":
		return loadDEB(rootfs)
	case "rpm":
		return loadRPM(rootfs)
	default:
		return nil, fmt.Errorf("unsupported distro type: %s", distro)
	}
}

func loadAPK(rootfs string) (map[string][]string, error) {
	path := filepath.Join(rootfs, "lib/apk/db/installed")
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading APK database: %w", err)
	}
	defer f.Close()

	result := make(map[string][]string)
	scanner := bufio.NewScanner(f)

	var currentPkg string
	var currentDir string

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			currentPkg = ""
			currentDir = ""
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		tag := line[0]
		value := line[2:]

		switch tag {
		case 'P':
			currentPkg = value
		case 'F':
			currentDir = "/" + value
		case 'R':
			if currentPkg != "" && currentDir != "" {
				fullPath := currentDir + "/" + value
				result[currentPkg] = append(result[currentPkg], fullPath)
			}
		}
	}

	return result, scanner.Err()
}

func loadDEB(rootfs string) (map[string][]string, error) {
	infoDir := filepath.Join(rootfs, "var/lib/dpkg/info")
	entries, err := os.ReadDir(infoDir)
	if err != nil {
		return nil, fmt.Errorf("reading dpkg info dir: %w", err)
	}

	result := make(map[string][]string)
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".list") {
			continue
		}
		pkgName := strings.TrimSuffix(name, ".list")
		if idx := strings.Index(pkgName, ":"); idx > 0 {
			pkgName = pkgName[:idx]
		}

		listPath := filepath.Join(infoDir, name)
		files, err := readLines(listPath)
		if err != nil {
			continue
		}
		result[pkgName] = files
	}

	return result, nil
}

func loadRPM(rootfs string) (map[string][]string, error) {
	manifestPath := filepath.Join(rootfs, "var/lib/rpm/Packages.manifest")
	if fileExists(manifestPath) {
		return loadRPMManifest(manifestPath)
	}

	rpmDir := filepath.Join(rootfs, "var/lib/rpm")
	if !dirExists(rpmDir) {
		rpmDir = filepath.Join(rootfs, "usr/lib/sysimage/rpm")
	}
	if !dirExists(rpmDir) {
		return nil, fmt.Errorf("RPM database not found in rootfs")
	}

	return make(map[string][]string), nil
}

func loadRPMManifest(path string) (map[string][]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	result := make(map[string][]string)
	scanner := bufio.NewScanner(f)
	var currentPkg string

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			currentPkg = ""
			continue
		}
		if !strings.HasPrefix(line, "/") {
			currentPkg = line
			continue
		}
		if currentPkg != "" {
			result[currentPkg] = append(result[currentPkg], line)
		}
	}

	return result, scanner.Err()
}

func classifyFile(p string) string {
	dir := posixpath.Dir(p)
	if pathDirs[dir] {
		return "binary"
	}
	for _, ld := range libDirs {
		if strings.HasPrefix(dir, ld) && isSharedLib(p) {
			return "library"
		}
	}
	return "other"
}

func isSharedLib(p string) bool {
	base := posixpath.Base(p)
	return strings.Contains(base, ".so")
}

func includeFile(fileType, level string) bool {
	switch level {
	case "binary":
		return fileType == "binary"
	case "library":
		return fileType == "binary" || fileType == "library"
	case "all":
		return true
	default:
		return fileType == "binary"
	}
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && strings.HasPrefix(line, "/") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
