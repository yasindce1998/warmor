package policygen

import (
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/yasindce1998/warmor/internal/streaming"
)

type Behavior struct {
	EventType string
	Comm      string
	Key       string
	Fields    map[string]any
	Count     int
	Paths     []string // raw path values before collapsing
}

type AggregateOptions struct {
	MinCount      int
	CollapsePaths bool
	NetworkGroup  string // "exact", "subnet", "any"
}

type AggregateResult struct {
	Behaviors  []*Behavior
	TotalEvents int
}

func Aggregate(events []streaming.SecurityEvent, opts AggregateOptions) *AggregateResult {
	buckets := make(map[string]*Behavior)

	for i := range events {
		ev := &events[i]
		key, fields, path := fingerprint(ev, opts.NetworkGroup)
		if key == "" {
			continue
		}

		if b, ok := buckets[key]; ok {
			b.Count++
			if path != "" && !containsString(b.Paths, path) {
				b.Paths = append(b.Paths, path)
			}
		} else {
			b := &Behavior{
				EventType: ev.EventType,
				Comm:      ev.Comm,
				Key:       key,
				Fields:    fields,
				Count:     1,
			}
			if path != "" {
				b.Paths = []string{path}
			}
			buckets[key] = b
		}
	}

	var behaviors []*Behavior
	for _, b := range buckets {
		if b.Count < opts.MinCount {
			continue
		}
		if opts.CollapsePaths && len(b.Paths) > 0 {
			b.Fields["collapsed_paths"] = collapsePaths(b.Paths)
		}
		behaviors = append(behaviors, b)
	}

	sort.Slice(behaviors, func(i, j int) bool {
		if behaviors[i].EventType != behaviors[j].EventType {
			return eventOrder(behaviors[i].EventType) < eventOrder(behaviors[j].EventType)
		}
		if behaviors[i].Comm != behaviors[j].Comm {
			return behaviors[i].Comm < behaviors[j].Comm
		}
		return behaviors[i].Key < behaviors[j].Key
	})

	return &AggregateResult{
		Behaviors:   behaviors,
		TotalEvents: len(events),
	}
}

func fingerprint(ev *streaming.SecurityEvent, networkGroup string) (key string, fields map[string]any, path string) {
	fields = make(map[string]any)

	switch ev.EventType {
	case "exec":
		fields["comm"] = ev.Comm
		fields["path"] = ev.Filename
		key = fmt.Sprintf("exec|%s|%s", ev.Comm, ev.Filename)
		path = ev.Filename

	case "file":
		fields["comm"] = ev.Comm
		fields["path"] = ev.Filename
		key = fmt.Sprintf("file|%s|%s", ev.Comm, ev.Filename)
		path = ev.Filename

	case "network":
		fields["comm"] = ev.Comm
		fields["protocol"] = ev.Protocol
		switch networkGroup {
		case "exact":
			fields["remote_addr"] = ev.RemoteAddr
			fields["remote_port"] = ev.RemotePort
			key = fmt.Sprintf("net|%s|%s|%s|%d", ev.Comm, ev.Protocol, ev.RemoteAddr, ev.RemotePort)
		case "subnet":
			subnet := toSubnet(ev.RemoteAddr)
			fields["remote_subnet"] = subnet
			fields["remote_port"] = ev.RemotePort
			key = fmt.Sprintf("net|%s|%s|%s|%d", ev.Comm, ev.Protocol, subnet, ev.RemotePort)
		case "any":
			fields["remote_port"] = ev.RemotePort
			key = fmt.Sprintf("net|%s|%s|%d", ev.Comm, ev.Protocol, ev.RemotePort)
		default:
			fields["remote_addr"] = ev.RemoteAddr
			fields["remote_port"] = ev.RemotePort
			key = fmt.Sprintf("net|%s|%s|%s|%d", ev.Comm, ev.Protocol, ev.RemoteAddr, ev.RemotePort)
		}
		if ev.LocalPort > 0 {
			fields["local_port"] = ev.LocalPort
		}

	default:
		return "", nil, ""
	}

	return key, fields, path
}

func toSubnet(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil {
		return addr
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return addr
	}
	return fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
}

var numericSegmentRe = regexp.MustCompile(`^[0-9a-f]{4,}$|^[0-9]+$`)

func collapsePaths(paths []string) any {
	if len(paths) <= 1 {
		return paths
	}

	groups := make(map[string][]string)
	for _, p := range paths {
		dir := filepath.Dir(p)
		groups[dir] = append(groups[dir], p)
	}

	var result []string
	for dir, members := range groups {
		if len(members) >= 3 {
			glob := tryGlob(dir, members)
			if glob != "" {
				result = append(result, glob)
				continue
			}
		}
		result = append(result, members...)
	}

	sort.Strings(result)
	if len(result) == 1 {
		return result[0]
	}
	return result
}

func tryGlob(dir string, paths []string) string {
	bases := make([]string, len(paths))
	for i, p := range paths {
		bases[i] = filepath.Base(p)
	}

	prefix := longestCommonPrefix(bases)
	suffix := longestCommonSuffix(bases)

	if len(prefix)+len(suffix) > 0 {
		for _, b := range bases {
			mid := b[len(prefix) : len(b)-len(suffix)]
			if mid == "" {
				return ""
			}
		}
		return filepath.Join(dir, prefix+"*"+suffix)
	}

	for _, b := range bases {
		parts := strings.Split(b, "/")
		for _, part := range parts {
			if numericSegmentRe.MatchString(part) {
				return filepath.Join(dir, "**")
			}
		}
	}

	return ""
}

func longestCommonPrefix(strs []string) string {
	if len(strs) == 0 {
		return ""
	}
	prefix := strs[0]
	for _, s := range strs[1:] {
		for !strings.HasPrefix(s, prefix) {
			prefix = prefix[:len(prefix)-1]
			if prefix == "" {
				return ""
			}
		}
	}
	return prefix
}

func longestCommonSuffix(strs []string) string {
	if len(strs) == 0 {
		return ""
	}
	suffix := strs[0]
	for _, s := range strs[1:] {
		for !strings.HasSuffix(s, suffix) {
			suffix = suffix[1:]
			if suffix == "" {
				return ""
			}
		}
	}
	return suffix
}

func containsString(sl []string, s string) bool {
	for _, v := range sl {
		if v == s {
			return true
		}
	}
	return false
}

func eventOrder(t string) int {
	switch t {
	case "exec":
		return 0
	case "file":
		return 1
	case "network":
		return 2
	default:
		return 3
	}
}
