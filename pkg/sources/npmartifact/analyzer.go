package npmartifact

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/attach-dev/attach-open-score/pkg/reasons"
	"github.com/attach-dev/attach-open-score/pkg/schema"
)

const (
	SourceName          = "npm-artifact"
	DefaultTTLSeconds   = 86400
	DefaultMaxBytes     = int64(25 << 20)
	DefaultMaxTotalSize = int64(50 << 20)
	DefaultMaxFiles     = 2000
	DefaultMaxTextBytes = int64(256 << 10)

	npmTermsURL = "https://docs.npmjs.com/policies/terms/"
)

var (
	lifecycleScriptNames = map[string]struct{}{
		"preinstall":  {},
		"install":     {},
		"postinstall": {},
		"prepare":     {},
	}
	jsEntryPattern   = regexp.MustCompile(`(?i)(?:^|[\s"'=])((?:\./|/)?[A-Za-z0-9_./@+-]+\.(?:js|cjs|mjs))`)
	base64Pattern    = regexp.MustCompile(`[A-Za-z0-9+/]{80,}={0,2}`)
	hexEscapePattern = regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
)

type Options struct {
	Now                 func() time.Time
	TTLSeconds          int
	MaxTarballBytes     int64
	MaxExtractedBytes   int64
	MaxFiles            int
	MaxTextBytesPerFile int64
}

type Analyzer struct {
	now                 func() time.Time
	ttlSeconds          int
	maxTarballBytes     int64
	maxExtractedBytes   int64
	maxFiles            int
	maxTextBytesPerFile int64
}

type PreviousManifest struct {
	Scripts              map[string]string `json:"scripts,omitempty"`
	Dependencies         map[string]string `json:"dependencies,omitempty"`
	DevDependencies      map[string]string `json:"devDependencies,omitempty"`
	OptionalDependencies map[string]string `json:"optionalDependencies,omitempty"`
	PeerDependencies     map[string]string `json:"peerDependencies,omitempty"`
}

type Result struct {
	Package  schema.PackageIdentity
	Evidence []schema.Evidence
}

type manifest struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Scripts              map[string]string `json:"scripts,omitempty"`
	Dependencies         map[string]string `json:"dependencies,omitempty"`
	DevDependencies      map[string]string `json:"devDependencies,omitempty"`
	OptionalDependencies map[string]string `json:"optionalDependencies,omitempty"`
	PeerDependencies     map[string]string `json:"peerDependencies,omitempty"`
}

type artifact struct {
	manifest       manifest
	files          map[string][]byte
	totalBytes     int64
	fileCount      int
	tarballSHA256  string
	packageJSONRaw []byte
}

type finding struct {
	Kind       string         `json:"kind"`
	Target     string         `json:"target,omitempty"`
	Pattern    string         `json:"pattern,omitempty"`
	Detail     string         `json:"detail,omitempty"`
	ScriptName string         `json:"script_name,omitempty"`
	Source     string         `json:"source,omitempty"`
	Extra      map[string]any `json:"extra,omitempty"`
}

func NewAnalyzer(options Options) (Analyzer, error) {
	now := options.Now
	if now == nil {
		now = time.Now
	}

	ttlSeconds := options.TTLSeconds
	if ttlSeconds == 0 {
		ttlSeconds = DefaultTTLSeconds
	}
	if ttlSeconds < 0 {
		return Analyzer{}, fmt.Errorf("npm artifact ttl_seconds must be non-negative")
	}

	maxBytes := options.MaxTarballBytes
	if maxBytes == 0 {
		maxBytes = DefaultMaxBytes
	}
	maxTotal := options.MaxExtractedBytes
	if maxTotal == 0 {
		maxTotal = DefaultMaxTotalSize
	}
	maxFiles := options.MaxFiles
	if maxFiles == 0 {
		maxFiles = DefaultMaxFiles
	}
	maxTextBytes := options.MaxTextBytesPerFile
	if maxTextBytes == 0 {
		maxTextBytes = DefaultMaxTextBytes
	}
	if maxBytes < 0 || maxTotal < 0 || maxFiles < 0 || maxTextBytes < 0 {
		return Analyzer{}, fmt.Errorf("npm artifact resource limits must be non-negative")
	}

	return Analyzer{
		now:                 now,
		ttlSeconds:          ttlSeconds,
		maxTarballBytes:     maxBytes,
		maxExtractedBytes:   maxTotal,
		maxFiles:            maxFiles,
		maxTextBytesPerFile: maxTextBytes,
	}, nil
}

func (a Analyzer) AnalyzeTarball(path string, pkg schema.PackageIdentity, previous *PreviousManifest, publishedAt string) (Result, error) {
	artifact, err := a.readTarball(path)
	if err != nil {
		return Result{}, err
	}

	pkg = completePackage(pkg, artifact.manifest)
	if err := validatePackage(pkg); err != nil {
		return Result{}, err
	}
	if artifact.manifest.Name != "" && artifact.manifest.Name != pkg.Name {
		return Result{}, fmt.Errorf("artifact package name %q does not match requested package %q", artifact.manifest.Name, pkg.Name)
	}
	if artifact.manifest.Version != "" && artifact.manifest.Version != pkg.Version {
		return Result{}, fmt.Errorf("artifact package version %q does not match requested version %q", artifact.manifest.Version, pkg.Version)
	}

	sourceRef := a.sourceRef(pkg, artifact.tarballSHA256)
	findings := analyzeArtifact(artifact, previous)
	if publishedAt != "" {
		if fresh, err := freshPublishFinding(publishedAt, a.now()); err != nil {
			return Result{}, err
		} else if fresh != nil {
			findings = append(findings, *fresh)
		}
	}

	evidence := evidenceFromFindings(pkg, sourceRef, artifact, findings)
	return Result{Package: pkg, Evidence: evidence}, nil
}

func (a Analyzer) readTarball(pathValue string) (artifact, error) {
	file, err := os.Open(pathValue)
	if err != nil {
		return artifact{}, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return artifact{}, err
	}
	if a.maxTarballBytes > 0 && info.Size() > a.maxTarballBytes {
		return artifact{}, fmt.Errorf("npm artifact tarball exceeds max bytes: %d > %d", info.Size(), a.maxTarballBytes)
	}

	hasher := sha256.New()
	limited := io.LimitReader(io.TeeReader(file, hasher), a.maxTarballBytes+1)
	gzipReader, err := gzip.NewReader(limited)
	if err != nil {
		return artifact{}, fmt.Errorf("read npm artifact gzip: %w", err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)
	out := artifact{files: map[string][]byte{}}
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return artifact{}, fmt.Errorf("read npm artifact tar: %w", err)
		}
		if header == nil {
			continue
		}
		name, err := cleanTarPath(header.Name)
		if err != nil {
			return artifact{}, err
		}
		switch header.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
		case tar.TypeSymlink, tar.TypeLink:
			return artifact{}, fmt.Errorf("npm artifact contains unsupported link entry %q", header.Name)
		default:
			continue
		}
		out.fileCount++
		if a.maxFiles > 0 && out.fileCount > a.maxFiles {
			return artifact{}, fmt.Errorf("npm artifact exceeds max file count: %d > %d", out.fileCount, a.maxFiles)
		}
		if header.Size < 0 {
			return artifact{}, fmt.Errorf("npm artifact file %q has negative size", header.Name)
		}
		out.totalBytes += header.Size
		if a.maxExtractedBytes > 0 && out.totalBytes > a.maxExtractedBytes {
			return artifact{}, fmt.Errorf("npm artifact exceeds max extracted bytes: %d > %d", out.totalBytes, a.maxExtractedBytes)
		}

		if shouldKeepFile(name, header.Size, a.maxTextBytesPerFile) {
			data, err := io.ReadAll(io.LimitReader(tarReader, a.maxTextBytesPerFile+1))
			if err != nil {
				return artifact{}, err
			}
			if int64(len(data)) <= a.maxTextBytesPerFile {
				out.files[name] = data
			}
		}
	}
	out.tarballSHA256 = hex.EncodeToString(hasher.Sum(nil))

	data, ok := out.files["package.json"]
	if !ok {
		return artifact{}, fmt.Errorf("npm artifact missing package.json")
	}
	out.packageJSONRaw = append([]byte(nil), data...)
	if err := json.Unmarshal(data, &out.manifest); err != nil {
		return artifact{}, fmt.Errorf("parse npm artifact package.json: %w", err)
	}
	return out, nil
}

func cleanTarPath(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("npm artifact contains empty path")
	}
	if path.IsAbs(value) || strings.Contains(value, "\\") {
		return "", fmt.Errorf("npm artifact contains unsafe path %q", value)
	}
	for _, part := range strings.Split(value, "/") {
		if part == ".." {
			return "", fmt.Errorf("npm artifact contains path traversal %q", value)
		}
	}
	clean := path.Clean(value)
	if strings.HasPrefix(clean, "package/") {
		clean = strings.TrimPrefix(clean, "package/")
	}
	if clean == "." || clean == "" {
		return "", fmt.Errorf("npm artifact contains unsafe path %q", value)
	}
	return clean, nil
}

func shouldKeepFile(name string, size, maxTextBytes int64) bool {
	if maxTextBytes > 0 && size > maxTextBytes {
		return false
	}
	if name == "package.json" {
		return true
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".js", ".cjs", ".mjs", ".json", ".sh", ".ps1", ".cmd", ".bat":
		return true
	default:
		return false
	}
}

func analyzeArtifact(artifact artifact, previous *PreviousManifest) []finding {
	findings := []finding{}
	lifecycleScripts := lifecycleScripts(artifact.manifest.Scripts)
	for name, command := range lifecycleScripts {
		f := finding{
			Kind:       "lifecycle_script",
			Target:     "package.json",
			ScriptName: name,
			Detail:     command,
		}
		if previous != nil && strings.TrimSpace(previous.Scripts[name]) == "" {
			f.Extra = map[string]any{"new_since_previous_manifest": true}
		}
		findings = append(findings, f)
		for _, match := range suspiciousTextFindings(command, "package.json scripts."+name, name) {
			findings = append(findings, match)
		}
		for _, entry := range scriptEntryFiles(command) {
			if data, ok := artifact.files[entry]; ok {
				for _, match := range suspiciousTextFindings(string(data), entry, name) {
					findings = append(findings, match)
				}
			}
		}
	}
	if previous != nil {
		for _, dep := range newDependencies(artifact.manifest, *previous) {
			findings = append(findings, finding{
				Kind:   "new_dependency",
				Target: dep,
			})
		}
	}
	return compactFindings(findings)
}

func lifecycleScripts(scripts map[string]string) map[string]string {
	out := map[string]string{}
	for name, command := range scripts {
		if _, ok := lifecycleScriptNames[name]; ok && strings.TrimSpace(command) != "" {
			out[name] = strings.TrimSpace(command)
		}
	}
	return out
}

func suspiciousTextFindings(text, target, scriptName string) []finding {
	patterns := []struct {
		kind    string
		pattern string
		needles []string
	}{
		{kind: "shell_process_usage", pattern: "child_process", needles: []string{"child_process", "execSync", "spawnSync", "exec(", "spawn("}},
		{kind: "install_time_download", pattern: "network_download", needles: []string{"curl ", "wget ", "Invoke-WebRequest", "http.get", "https.get", "fetch(", "http://", "https://"}},
		{kind: "install_time_execute", pattern: "execute_payload", needles: []string{"chmod +x", "bash -c", "sh -c", "powershell", "Start-Process"}},
		{kind: "obfuscation_marker", pattern: "dynamic_code", needles: []string{"eval(", "Function(", "String.fromCharCode", "atob(", "Buffer.from("}},
	}
	lower := strings.ToLower(text)
	out := []finding{}
	for _, group := range patterns {
		for _, needle := range group.needles {
			if strings.Contains(lower, strings.ToLower(needle)) {
				out = append(out, finding{Kind: group.kind, Target: target, Pattern: group.pattern, Detail: needle, ScriptName: scriptName})
				break
			}
		}
	}
	if base64Pattern.FindString(text) != "" {
		out = append(out, finding{Kind: "obfuscation_marker", Target: target, Pattern: "long_base64_literal", ScriptName: scriptName})
	}
	if len(hexEscapePattern.FindAllString(text, 20)) >= 20 {
		out = append(out, finding{Kind: "obfuscation_marker", Target: target, Pattern: "many_hex_escapes", ScriptName: scriptName})
	}
	return out
}

func scriptEntryFiles(command string) []string {
	matches := jsEntryPattern.FindAllStringSubmatch(command, -1)
	out := []string{}
	seen := map[string]struct{}{}
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		candidate := path.Clean(strings.TrimPrefix(match[1], "./"))
		if candidate == "." || strings.HasPrefix(candidate, "../") {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	return out
}

func newDependencies(current manifest, previous PreviousManifest) []string {
	currentDeps := mergeDeps(current.Dependencies, current.DevDependencies, current.OptionalDependencies, current.PeerDependencies)
	previousDeps := mergeDeps(previous.Dependencies, previous.DevDependencies, previous.OptionalDependencies, previous.PeerDependencies)
	out := []string{}
	for name, version := range currentDeps {
		if _, ok := previousDeps[name]; !ok {
			out = append(out, name+"@"+version)
		}
	}
	sort.Strings(out)
	return out
}

func mergeDeps(groups ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, group := range groups {
		for name, version := range group {
			if strings.TrimSpace(name) != "" {
				out[name] = strings.TrimSpace(version)
			}
		}
	}
	return out
}

func compactFindings(in []finding) []finding {
	out := []finding{}
	seen := map[string]struct{}{}
	for _, item := range in {
		key := item.Kind + "\x00" + item.Target + "\x00" + item.Pattern + "\x00" + item.ScriptName + "\x00" + item.Detail
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func freshPublishFinding(publishedAt string, now time.Time) (*finding, error) {
	published, err := time.Parse(time.RFC3339, publishedAt)
	if err != nil {
		return nil, fmt.Errorf("parse published_at: %w", err)
	}
	age := now.Sub(published)
	if age < 0 {
		age = 0
	}
	if age <= 24*time.Hour {
		return &finding{
			Kind:   "fresh_publish",
			Target: "npm registry metadata",
			Detail: published.UTC().Format(time.RFC3339),
			Extra:  map[string]any{"age_seconds": int(age.Seconds())},
		}, nil
	}
	return nil, nil
}

func evidenceFromFindings(pkg schema.PackageIdentity, sourceRef schema.SourceRef, artifact artifact, findings []finding) []schema.Evidence {
	if len(findings) == 0 {
		return []schema.Evidence{{
			Reason: schema.Reason{
				Code:           reasons.NoSuspiciousArtifactSignals,
				Severity:       "INFO",
				DecisionEffect: schema.DecisionEffectNone,
				Message:        fmt.Sprintf("Deterministic npm artifact analysis found no suspicious install-time artifact signals for %s@%s.", pkg.Name, pkg.Version),
				SourceRefIDs:   []string{sourceRef.ID},
				Details:        artifactDetails(artifact, nil),
			},
			SourceRef: &sourceRef,
		}}
	}

	var installScripts []finding
	var suspicious []finding
	var fresh []finding
	var deps []finding
	for _, item := range findings {
		switch item.Kind {
		case "lifecycle_script":
			installScripts = append(installScripts, item)
		case "fresh_publish":
			fresh = append(fresh, item)
		case "new_dependency":
			deps = append(deps, item)
		default:
			suspicious = append(suspicious, item)
		}
	}

	out := []schema.Evidence{}
	if len(installScripts) > 0 {
		out = append(out, schema.Evidence{
			Reason: schema.Reason{
				Code:           reasons.InstallScriptPresent,
				Severity:       "MEDIUM",
				DecisionEffect: schema.DecisionEffectAsk,
				Message:        fmt.Sprintf("npm artifact %s@%s declares install-time lifecycle scripts.", pkg.Name, pkg.Version),
				SourceRefIDs:   []string{sourceRef.ID},
				Details:        artifactDetails(artifact, map[string]any{"findings": installScripts, "new_dependencies": deps}),
			},
			SourceRef: &sourceRef,
		})
	}
	if len(suspicious) > 0 {
		out = append(out, schema.Evidence{
			Reason: schema.Reason{
				Code:           reasons.SuspiciousInstallScript,
				Severity:       "HIGH",
				DecisionEffect: schema.DecisionEffectAsk,
				Message:        fmt.Sprintf("npm artifact %s@%s has suspicious install-time script behavior.", pkg.Name, pkg.Version),
				SourceRefIDs:   []string{sourceRef.ID},
				Details:        artifactDetails(artifact, map[string]any{"findings": suspicious}),
			},
			SourceRef: &sourceRef,
		})
	}
	for _, item := range fresh {
		out = append(out, schema.Evidence{
			Reason: schema.Reason{
				Code:           reasons.VersionTooNew,
				Severity:       "MEDIUM",
				DecisionEffect: schema.DecisionEffectAsk,
				Message:        fmt.Sprintf("npm artifact %s@%s was published recently.", pkg.Name, pkg.Version),
				SourceRefIDs:   []string{sourceRef.ID},
				Details:        artifactDetails(artifact, map[string]any{"finding": item}),
			},
			SourceRef: &sourceRef,
		})
	}
	if len(out) == 0 {
		out = append(out, schema.Evidence{
			Reason: schema.Reason{
				Code:           reasons.NoSuspiciousArtifactSignals,
				Severity:       "INFO",
				DecisionEffect: schema.DecisionEffectNone,
				Message:        fmt.Sprintf("Deterministic npm artifact analysis found no suspicious install-time artifact signals for %s@%s.", pkg.Name, pkg.Version),
				SourceRefIDs:   []string{sourceRef.ID},
				Details:        artifactDetails(artifact, map[string]any{"new_dependencies": deps}),
			},
			SourceRef: &sourceRef,
		})
	}
	return out
}

func artifactDetails(artifact artifact, extra map[string]any) map[string]any {
	details := map[string]any{
		"tarball_sha256":        artifact.tarballSHA256,
		"file_count":            artifact.fileCount,
		"extracted_total_bytes": artifact.totalBytes,
	}
	for key, value := range extra {
		details[key] = value
	}
	return details
}

func completePackage(pkg schema.PackageIdentity, manifest manifest) schema.PackageIdentity {
	if pkg.Ecosystem == "" {
		pkg.Ecosystem = "npm"
	}
	if pkg.Name == "" {
		pkg.Name = strings.TrimSpace(manifest.Name)
	}
	if pkg.Version == "" {
		pkg.Version = strings.TrimSpace(manifest.Version)
	}
	if pkg.PURL == "" && pkg.Name != "" && pkg.Version != "" {
		pkg.PURL = "pkg:npm/" + url.PathEscape(pkg.Name) + "@" + url.PathEscape(pkg.Version)
	}
	pkg.Resolved = true
	return pkg
}

func validatePackage(pkg schema.PackageIdentity) error {
	if pkg.Ecosystem != "npm" {
		return fmt.Errorf("npm artifact analyzer only supports npm ecosystem, got %q", pkg.Ecosystem)
	}
	if strings.TrimSpace(pkg.Name) == "" {
		return fmt.Errorf("npm artifact package name is required")
	}
	if strings.TrimSpace(pkg.Version) == "" {
		return fmt.Errorf("npm artifact package version is required")
	}
	if strings.TrimSpace(pkg.PURL) == "" {
		return fmt.Errorf("npm artifact package purl is required")
	}
	return nil
}

func (a Analyzer) sourceRef(pkg schema.PackageIdentity, digest string) schema.SourceRef {
	escapedName := strings.ReplaceAll(url.PathEscape(pkg.Name), "%2F", "/")
	return schema.SourceRef{
		ID:                  sourceRefID(pkg.Name, pkg.Version, digest),
		Source:              SourceName,
		SourceID:            pkg.Name + "@" + pkg.Version + "#sha256:" + digest,
		URL:                 "https://registry.npmjs.org/" + escapedName + "/-/" + url.PathEscape(tarballName(pkg.Name, pkg.Version)),
		RetrievedAt:         a.now().UTC().Format(time.RFC3339),
		TTLSeconds:          a.ttlSeconds,
		LicenseOrTermsURL:   npmTermsURL,
		Attribution:         "Deterministic local analysis of an npm package tarball; npm package metadata and artifacts remain subject to npm terms.",
		AttributionRequired: true,
		Redistribution:      "unknown",
		PublicDisplay:       "allowed",
	}
}

func sourceRefID(name, version, digest string) string {
	value := strings.ToLower(name + "-" + version + "-" + digest)
	replacer := strings.NewReplacer("/", "-", "@", "", "_", "-", ".", "-")
	return "npm-artifact-" + replacer.Replace(value)
}

func tarballName(name, version string) string {
	base := name
	if strings.Contains(base, "/") {
		parts := strings.Split(base, "/")
		base = parts[len(parts)-1]
	}
	return base + "-" + version + ".tgz"
}

func LoadPreviousManifest(pathValue string) (*PreviousManifest, error) {
	if pathValue == "" {
		return nil, nil
	}
	data, err := os.ReadFile(pathValue)
	if err != nil {
		return nil, err
	}
	var manifest PreviousManifest
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	if err := decoder.Decode(&manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}
