package depsdev

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/attach-dev/attach-open-score/pkg/reasons"
	"github.com/attach-dev/attach-open-score/pkg/schema"
	"github.com/attach-dev/attach-open-score/pkg/sources"
)

const (
	DefaultTTLSeconds = 86400

	SourceName        = "deps.dev"
	licenseOrTermsURL = "https://docs.deps.dev/api/v3/"
	apiScheme         = "https"
	apiHost           = "api.deps.dev"
)

var sourceRefIDReplacer = regexp.MustCompile(`[^a-z0-9._-]+`)

type Options struct {
	Now        func() time.Time
	TTLSeconds int
}

type Adapter struct {
	now        func() time.Time
	ttlSeconds int
}

type Metadata struct {
	Package              Package          `json:"package,omitempty"`
	Version              Version          `json:"version,omitempty"`
	PackageKey           PackageKey       `json:"packageKey,omitempty"`
	VersionKey           VersionKey       `json:"versionKey,omitempty"`
	Description          string           `json:"description,omitempty"`
	PublishedAt          string           `json:"publishedAt,omitempty"`
	IsDefault            bool             `json:"isDefault,omitempty"`
	Links                []Link           `json:"links,omitempty"`
	Versions             []Version        `json:"versions,omitempty"`
	Licenses             Licenses         `json:"licenses,omitempty"`
	Dependencies         []Dependency     `json:"dependencies,omitempty"`
	Nodes                []DependencyNode `json:"nodes,omitempty"`
	Edges                []DependencyEdge `json:"edges,omitempty"`
	DependencyGraph      DependencyGraph  `json:"dependencyGraph,omitempty"`
	DependencyGraphSnake DependencyGraph  `json:"dependency_graph,omitempty"`
	Projects             []Project        `json:"projects,omitempty"`
}

type Package struct {
	PackageKey  PackageKey      `json:"packageKey,omitempty"`
	System      string          `json:"system,omitempty"`
	Name        string          `json:"name,omitempty"`
	Description string          `json:"description,omitempty"`
	Links       []Link          `json:"links,omitempty"`
	Versions    []Version       `json:"versions,omitempty"`
	Projects    []Project       `json:"projects,omitempty"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
}

type Version struct {
	VersionKey           VersionKey      `json:"versionKey,omitempty"`
	System               string          `json:"system,omitempty"`
	Name                 string          `json:"name,omitempty"`
	Version              string          `json:"version,omitempty"`
	PublishedAt          string          `json:"publishedAt,omitempty"`
	IsDefault            bool            `json:"isDefault,omitempty"`
	Licenses             Licenses        `json:"licenses,omitempty"`
	Links                []Link          `json:"links,omitempty"`
	Dependencies         []Dependency    `json:"dependencies,omitempty"`
	DependencyGraph      DependencyGraph `json:"dependencyGraph,omitempty"`
	DependencyGraphSnake DependencyGraph `json:"dependency_graph,omitempty"`
	Projects             []Project       `json:"projects,omitempty"`
}

type PackageKey struct {
	System string `json:"system,omitempty"`
	Name   string `json:"name,omitempty"`
}

type VersionKey struct {
	System  string `json:"system,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

type Link struct {
	Label string `json:"label,omitempty"`
	Type  string `json:"type,omitempty"`
	URL   string `json:"url,omitempty"`
}

type Project struct {
	Type  string `json:"type,omitempty"`
	Name  string `json:"name,omitempty"`
	URL   string `json:"url,omitempty"`
	Links []Link `json:"links,omitempty"`
}

type Dependency struct {
	PackageKey  PackageKey `json:"packageKey,omitempty"`
	VersionKey  VersionKey `json:"versionKey,omitempty"`
	System      string     `json:"system,omitempty"`
	Name        string     `json:"name,omitempty"`
	Version     string     `json:"version,omitempty"`
	Requirement string     `json:"requirement,omitempty"`
	Relation    string     `json:"relation,omitempty"`
	Type        string     `json:"type,omitempty"`
	Scope       string     `json:"scope,omitempty"`
}

type DependencyGraph struct {
	Nodes []DependencyNode `json:"nodes,omitempty"`
	Edges []DependencyEdge `json:"edges,omitempty"`
	Error string           `json:"error,omitempty"`
}

type DependencyNode struct {
	VersionKey VersionKey `json:"versionKey,omitempty"`
	PackageKey PackageKey `json:"packageKey,omitempty"`
	Relation   string     `json:"relation,omitempty"`
	Bundled    bool       `json:"bundled,omitempty"`
	Errors     []string   `json:"errors,omitempty"`
}

type DependencyEdge struct {
	FromNode    int    `json:"fromNode,omitempty"`
	ToNode      int    `json:"toNode,omitempty"`
	Requirement string `json:"requirement,omitempty"`
}

type Licenses []string

func NewAdapter(options Options) (Adapter, error) {
	now := options.Now
	if now == nil {
		now = time.Now
	}

	ttlSeconds := options.TTLSeconds
	if ttlSeconds == 0 {
		ttlSeconds = DefaultTTLSeconds
	}
	if ttlSeconds < 0 {
		return Adapter{}, fmt.Errorf("deps.dev ttl_seconds must be non-negative")
	}

	return Adapter{
		now:        now,
		ttlSeconds: ttlSeconds,
	}, nil
}

func (a Adapter) Evidence(metadata Metadata) ([]schema.Evidence, error) {
	return a.evidence(metadata, a.recordSetSourceRef()), nil
}

func (a Adapter) EvidenceFromJSON(data []byte) ([]schema.Evidence, error) {
	sourceRef := a.localJSONSourceRef(data)
	metadata, err := parseMetadata(data)
	if err != nil {
		return []schema.Evidence{a.sourceUnavailableEvidence(sourceRef, nil, "parse_failure", map[string]any{
			"parse_error": err.Error(),
		})}, nil
	}

	return a.evidence(metadata, sourceRef), nil
}

func parseMetadata(data []byte) (Metadata, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return Metadata{}, errors.New("empty deps.dev metadata JSON")
	}
	if data[0] == '[' {
		return Metadata{}, errors.New("deps.dev metadata JSON must be an object")
	}

	var metadata Metadata
	if err := decodeJSON(data, &metadata); err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}

func decodeJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("deps.dev metadata JSON contains trailing data")
	}
	return nil
}

func (l *Licenses) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}

	var values []string
	if err := json.Unmarshal(data, &values); err == nil {
		*l = normalizeStringList(values)
		return nil
	}

	var objects []map[string]any
	if err := json.Unmarshal(data, &objects); err != nil {
		return err
	}

	for _, object := range objects {
		for _, key := range []string{"spdx", "spdx_id", "id", "license", "name"} {
			if value, ok := object[key].(string); ok {
				if value = strings.TrimSpace(value); value != "" {
					values = append(values, value)
					break
				}
			}
		}
	}
	*l = normalizeStringList(values)
	return nil
}

func (a Adapter) evidence(metadata Metadata, fallbackSourceRef schema.SourceRef) []schema.Evidence {
	normalized, validation := normalizeMetadata(metadata)
	if !validation.ok {
		return []schema.Evidence{a.sourceUnavailableEvidence(fallbackSourceRef, nil, validation.failureKind, validation.details())}
	}

	sourceRefs := a.sourceRefs(metadata, normalized)
	sourceRef := sourceRefs[0]
	sourceRefIDs := sourceRefIDs(sourceRefs)
	details := metadataDetails(metadata, normalized)
	if len(sourceRefs) > 1 {
		details["source_refs"] = sourceRefDetails(sourceRefs)
	}

	return []schema.Evidence{{
		Reason: schema.Reason{
			Code:           reasons.RepositoryMappingUncertain,
			Severity:       "MEDIUM",
			DecisionEffect: schema.DecisionEffectUnknown,
			Message:        fmt.Sprintf("deps.dev metadata for %s package %s@%s was normalized as non-authoritative package and repository context only.", normalized.Ecosystem, normalized.Name, normalized.Version),
			SourceRefIDs:   sourceRefIDs,
			Details:        details,
		},
		SourceRef:  &sourceRef,
		SourceRefs: sourceRefs[1:],
	}}
}

type metadataValidation struct {
	ok          bool
	failureKind string
	missing     []string
	conflicts   []string
}

func (v metadataValidation) details() map[string]any {
	details := map[string]any{
		"source": SourceName,
	}
	if len(v.missing) > 0 {
		details["missing_fields"] = v.missing
	}
	if len(v.conflicts) > 0 {
		details["conflicting_fields"] = v.conflicts
	}
	return details
}

type normalizedMetadata struct {
	System     string
	Ecosystem  string
	Name       string
	Version    string
	PURL       string
	SourceID   string
	PackageID  string
	VersionURL string
	PackageURL string
}

func normalizeMetadata(metadata Metadata) (normalizedMetadata, metadataValidation) {
	var builder identityBuilder
	addPackageKey(&builder, "package.packageKey", metadata.Package.PackageKey)
	builder.addSystem("package.system", metadata.Package.System)
	builder.addName("package.name", metadata.Package.Name)
	addVersionKey(&builder, "version.versionKey", metadata.Version.VersionKey)
	builder.addSystem("version.system", metadata.Version.System)
	builder.addName("version.name", metadata.Version.Name)
	builder.addVersion("version.version", metadata.Version.Version)
	addPackageKey(&builder, "packageKey", metadata.PackageKey)
	addVersionKey(&builder, "versionKey", metadata.VersionKey)
	addGraphSelfNodeIdentity(&builder, "nodes", DependencyGraph{Nodes: metadata.Nodes, Edges: metadata.Edges})
	addGraphSelfNodeIdentity(&builder, "dependencyGraph", metadata.DependencyGraph)
	addGraphSelfNodeIdentity(&builder, "dependency_graph", metadata.DependencyGraphSnake)
	addGraphSelfNodeIdentity(&builder, "version.dependencyGraph", metadata.Version.DependencyGraph)
	addGraphSelfNodeIdentity(&builder, "version.dependency_graph", metadata.Version.DependencyGraphSnake)

	versions := append([]Version{}, metadata.Package.Versions...)
	versions = append(versions, metadata.Versions...)
	if builder.version == "" && len(versions) == 1 {
		addVersionKey(&builder, "versions[0].versionKey", versions[0].VersionKey)
		builder.addVersion("versions[0].version", versions[0].Version)
	}
	if builder.version == "" && len(versions) > 1 {
		builder.conflicts = append(builder.conflicts, "versions")
	}

	missing := []string{}
	if builder.system == "" {
		missing = append(missing, "system")
	}
	if builder.name == "" {
		missing = append(missing, "name")
	}
	if builder.version == "" {
		missing = append(missing, "version")
	}
	if len(builder.conflicts) > 0 {
		return normalizedMetadata{}, metadataValidation{failureKind: "conflicting_required_data", conflicts: builder.conflicts}
	}
	if len(missing) > 0 {
		return normalizedMetadata{}, metadataValidation{failureKind: "missing_required_data", missing: missing}
	}

	system := normalizeSystem(builder.system)
	ecosystem := ecosystemFromSystem(system)
	normalized := normalizedMetadata{
		System:    system,
		Ecosystem: ecosystem,
		Name:      builder.name,
		Version:   builder.version,
	}
	normalized.PURL = purl(ecosystem, normalized.Name, normalized.Version)
	normalized.SourceID = versionSourceID(normalized)
	normalized.PackageID = packageSourceID(normalized)
	normalized.VersionURL = versionAPIURL(normalized)
	normalized.PackageURL = packageAPIURL(normalized)
	return normalized, metadataValidation{ok: true}
}

type identityBuilder struct {
	system    string
	name      string
	version   string
	conflicts []string
}

func addPackageKey(builder *identityBuilder, field string, key PackageKey) {
	builder.addSystem(field+".system", key.System)
	builder.addName(field+".name", key.Name)
}

func addVersionKey(builder *identityBuilder, field string, key VersionKey) {
	builder.addSystem(field+".system", key.System)
	builder.addName(field+".name", key.Name)
	builder.addVersion(field+".version", key.Version)
}

func addGraphSelfNodeIdentity(builder *identityBuilder, field string, graph DependencyGraph) {
	for i, node := range graph.Nodes {
		if !strings.EqualFold(strings.TrimSpace(node.Relation), "SELF") {
			continue
		}
		nodeField := fmt.Sprintf("%s[%d]", field, i)
		addVersionKey(builder, nodeField+".versionKey", node.VersionKey)
		addPackageKey(builder, nodeField+".packageKey", node.PackageKey)
	}
}

func (b *identityBuilder) addSystem(field, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	value = normalizeSystem(value)
	if b.system == "" {
		b.system = value
		return
	}
	if b.system != value {
		b.conflicts = append(b.conflicts, field)
	}
}

func (b *identityBuilder) addName(field, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	if b.name == "" {
		b.name = value
		return
	}
	if b.name != value {
		b.conflicts = append(b.conflicts, field)
	}
}

func (b *identityBuilder) addVersion(field, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	if b.version == "" {
		b.version = value
		return
	}
	if b.version != value {
		b.conflicts = append(b.conflicts, field)
	}
}

func normalizeSystem(system string) string {
	switch strings.ToLower(strings.TrimSpace(system)) {
	case "npm":
		return "NPM"
	case "pypi", "pip", "python":
		return "PYPI"
	case "cargo", "crates", "crates.io", "rust":
		return "CARGO"
	case "go", "golang", "gomod":
		return "GO"
	case "maven":
		return "MAVEN"
	case "nuget":
		return "NUGET"
	default:
		return strings.ToUpper(strings.TrimSpace(system))
	}
}

func ecosystemFromSystem(system string) string {
	switch normalizeSystem(system) {
	case "NPM":
		return "npm"
	case "PYPI":
		return "pypi"
	case "CARGO":
		return "crates"
	case "GO":
		return "go"
	case "MAVEN":
		return "maven"
	case "NUGET":
		return "other"
	default:
		return "other"
	}
}

func metadataDetails(metadata Metadata, normalized normalizedMetadata) map[string]any {
	details := map[string]any{
		"source":         SourceName,
		"ecosystem":      normalized.Ecosystem,
		"depsdev_system": normalized.System,
		"package_name":   normalized.Name,
		"version":        normalized.Version,
		"purl":           normalized.PURL,
	}

	if description := strings.TrimSpace(firstNonEmpty(metadata.Package.Description, metadata.Description)); description != "" {
		details["description"] = description
	}
	if publishedAt := strings.TrimSpace(firstNonEmpty(metadata.Version.PublishedAt, metadata.PublishedAt)); publishedAt != "" {
		details["published_at"] = publishedAt
	}
	if metadata.Version.IsDefault || metadata.IsDefault {
		details["is_default"] = true
	}
	versions := append([]Version{}, metadata.Package.Versions...)
	versions = append(versions, metadata.Versions...)
	if versions := packageVersionDetails(versions); len(versions) > 0 {
		details["package_versions"] = versions
	}

	licenses := licensesFromMetadata(metadata)
	if len(licenses) > 0 {
		details["licenses"] = licenses
		details["license_metadata_status"] = "reported_by_deps_dev"
	} else {
		details["license_metadata_status"] = "not_reported"
	}

	dependencies := dependencyDetails(metadata)
	if len(dependencies) > 0 {
		details["dependencies"] = dependencies
		details["dependency_count"] = len(dependencies)
		details["dependency_metadata_status"] = "reported_by_deps_dev"
	} else {
		details["dependency_metadata_status"] = "not_reported"
	}

	repositoryLinks := repositoryLinkDetails(metadata)
	if len(repositoryLinks) > 0 {
		details["repository_links"] = repositoryLinks
		if len(repositoryLinks) == 1 {
			details["repository_mapping_status"] = "reported_by_deps_dev"
		} else {
			details["repository_mapping_status"] = "ambiguous"
		}
	} else {
		details["repository_mapping_status"] = "not_reported"
	}

	return details
}

func packageVersionDetails(versions []Version) []map[string]any {
	if len(versions) == 0 {
		return nil
	}
	details := make([]map[string]any, 0, len(versions))
	seen := map[string]struct{}{}
	for _, version := range versions {
		value := firstNonEmpty(version.VersionKey.Version, version.Version)
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		item := map[string]any{"version": value}
		if publishedAt := strings.TrimSpace(version.PublishedAt); publishedAt != "" {
			item["published_at"] = publishedAt
		}
		if version.IsDefault {
			item["is_default"] = true
		}
		details = append(details, item)
	}
	return details
}

func licensesFromMetadata(metadata Metadata) []string {
	values := []string{}
	values = append(values, metadata.Licenses...)
	values = append(values, metadata.Version.Licenses...)
	return normalizeStringList(values)
}

func dependencyDetails(metadata Metadata) []map[string]string {
	dependencies := []normalizedDependency{}
	dependencies = append(dependencies, normalizeDependencies(metadata.Dependencies)...)
	dependencies = append(dependencies, normalizeDependencies(metadata.Version.Dependencies)...)
	dependencies = append(dependencies, dependenciesFromGraph(DependencyGraph{Nodes: metadata.Nodes, Edges: metadata.Edges})...)
	dependencies = append(dependencies, dependenciesFromGraph(metadata.DependencyGraph)...)
	dependencies = append(dependencies, dependenciesFromGraph(metadata.DependencyGraphSnake)...)
	dependencies = append(dependencies, dependenciesFromGraph(metadata.Version.DependencyGraph)...)
	dependencies = append(dependencies, dependenciesFromGraph(metadata.Version.DependencyGraphSnake)...)

	return normalizedDependencyDetails(dependencies)
}

type normalizedDependency struct {
	System      string
	Name        string
	Version     string
	Requirement string
	Relation    string
	Type        string
	Scope       string
	Bundled     bool
}

func normalizeDependencies(dependencies []Dependency) []normalizedDependency {
	normalized := make([]normalizedDependency, 0, len(dependencies))
	for _, dependency := range dependencies {
		system := firstNonEmpty(dependency.VersionKey.System, dependency.PackageKey.System, dependency.System)
		name := firstNonEmpty(dependency.VersionKey.Name, dependency.PackageKey.Name, dependency.Name)
		version := firstNonEmpty(dependency.VersionKey.Version, dependency.Version)
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		item := normalizedDependency{
			System:      normalizeSystem(system),
			Name:        name,
			Version:     strings.TrimSpace(version),
			Requirement: strings.TrimSpace(dependency.Requirement),
			Relation:    strings.TrimSpace(dependency.Relation),
			Type:        strings.TrimSpace(dependency.Type),
			Scope:       strings.TrimSpace(dependency.Scope),
		}
		normalized = append(normalized, item)
	}
	return normalized
}

func dependenciesFromGraph(graph DependencyGraph) []normalizedDependency {
	if len(graph.Nodes) == 0 {
		return nil
	}

	requirementsByNode := map[int][]string{}
	for _, edge := range graph.Edges {
		if edge.ToNode < 0 || edge.ToNode >= len(graph.Nodes) {
			continue
		}
		requirement := strings.TrimSpace(edge.Requirement)
		if requirement == "" {
			continue
		}
		requirementsByNode[edge.ToNode] = append(requirementsByNode[edge.ToNode], requirement)
	}
	for node := range requirementsByNode {
		slices.Sort(requirementsByNode[node])
		requirementsByNode[node] = compactStrings(requirementsByNode[node])
	}

	dependencies := make([]normalizedDependency, 0, len(graph.Nodes))
	for i, node := range graph.Nodes {
		relation := strings.TrimSpace(node.Relation)
		if strings.EqualFold(relation, "SELF") {
			continue
		}
		system := firstNonEmpty(node.VersionKey.System, node.PackageKey.System)
		name := firstNonEmpty(node.VersionKey.Name, node.PackageKey.Name)
		version := strings.TrimSpace(node.VersionKey.Version)
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		dependency := normalizedDependency{
			System:   normalizeSystem(system),
			Name:     name,
			Version:  version,
			Relation: relation,
			Bundled:  node.Bundled,
		}
		if requirements := requirementsByNode[i]; len(requirements) > 0 {
			dependency.Requirement = strings.Join(requirements, ", ")
		}
		dependencies = append(dependencies, dependency)
	}
	return dependencies
}

func normalizedDependencyDetails(dependencies []normalizedDependency) []map[string]string {
	if len(dependencies) == 0 {
		return nil
	}

	details := make([]map[string]string, 0, len(dependencies))
	seen := map[string]struct{}{}
	for _, dependency := range dependencies {
		item := map[string]string{"name": dependency.Name}
		if dependency.System != "" {
			item["system"] = dependency.System
		}
		if dependency.Version != "" {
			item["version"] = dependency.Version
		}
		if dependency.Requirement != "" {
			item["requirement"] = dependency.Requirement
		}
		if dependency.Relation != "" {
			item["relation"] = dependency.Relation
		}
		if dependency.Type != "" {
			item["type"] = dependency.Type
		}
		if dependency.Scope != "" {
			item["scope"] = dependency.Scope
		}
		if dependency.Bundled {
			item["bundled"] = "true"
		}

		key := dependencyKey(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		details = append(details, item)
	}
	return details
}

func dependencyKey(item map[string]string) string {
	keys := make([]string, 0, len(item))
	for key := range item {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	var builder strings.Builder
	for _, key := range keys {
		builder.WriteString(key)
		builder.WriteByte('=')
		builder.WriteString(item[key])
		builder.WriteByte(';')
	}
	return builder.String()
}

func repositoryLinkDetails(metadata Metadata) []map[string]string {
	links := repositoryLinks(metadata)
	if len(links) == 0 {
		return nil
	}

	details := make([]map[string]string, 0, len(links))
	for _, link := range links {
		item := map[string]string{"url": strings.TrimSpace(link.URL)}
		if label := strings.TrimSpace(link.Label); label != "" {
			item["label"] = label
		}
		if linkType := strings.TrimSpace(link.Type); linkType != "" {
			item["type"] = linkType
		}
		details = append(details, item)
	}
	return details
}

func repositoryLinks(metadata Metadata) []Link {
	candidates := []Link{}
	candidates = append(candidates, metadata.Links...)
	candidates = append(candidates, metadata.Package.Links...)
	candidates = append(candidates, metadata.Version.Links...)
	candidates = append(candidates, projectLinks(metadata.Projects)...)
	candidates = append(candidates, projectLinks(metadata.Package.Projects)...)
	candidates = append(candidates, projectLinks(metadata.Version.Projects)...)

	links := []Link{}
	seen := map[string]struct{}{}
	for _, link := range candidates {
		link.URL = strings.TrimSpace(link.URL)
		if !isRepositoryLink(link) {
			continue
		}
		normalizedURL := canonicalURL(link.URL)
		if normalizedURL == "" {
			continue
		}
		if _, ok := seen[normalizedURL]; ok {
			continue
		}
		seen[normalizedURL] = struct{}{}
		link.URL = normalizedURL
		links = append(links, link)
	}
	return links
}

func projectLinks(projects []Project) []Link {
	links := []Link{}
	for _, project := range projects {
		if strings.TrimSpace(project.URL) != "" {
			links = append(links, Link{
				Label: firstNonEmpty(project.Type, "PROJECT"),
				URL:   project.URL,
			})
		}
		links = append(links, project.Links...)
	}
	return links
}

func isRepositoryLink(link Link) bool {
	if strings.TrimSpace(link.URL) == "" {
		return false
	}
	label := strings.ToLower(strings.TrimSpace(firstNonEmpty(link.Label, link.Type)))
	if strings.Contains(label, "repo") || strings.Contains(label, "source") || strings.Contains(label, "vcs") {
		return isValidURI(link.URL)
	}

	parsed, err := url.ParseRequestURI(link.URL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	host := strings.ToLower(parsed.Host)
	if strings.HasPrefix(host, "www.") {
		host = strings.TrimPrefix(host, "www.")
	}
	switch host {
	case "github.com", "gitlab.com", "bitbucket.org", "sr.ht", "sourcehut.org":
		return true
	default:
		return strings.HasSuffix(strings.TrimSuffix(parsed.Path, "/"), ".git")
	}
}

func canonicalURL(value string) string {
	parsed, err := url.ParseRequestURI(strings.TrimSpace(value))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	parsed.Fragment = ""
	return parsed.String()
}

func isValidURI(value string) bool {
	return canonicalURL(value) != ""
}

func (a Adapter) sourceRefs(metadata Metadata, normalized normalizedMetadata) []schema.SourceRef {
	refs := []schema.SourceRef{
		a.versionSourceRef(normalized),
		a.packageSourceRef(normalized),
	}
	if len(dependencyDetails(metadata)) > 0 {
		refs = append(refs, a.dependenciesSourceRef(normalized))
	}
	for _, link := range repositoryLinks(metadata) {
		refs = append(refs, a.linkSourceRef(link))
	}
	return dedupeSourceRefs(refs)
}

func dedupeSourceRefs(sourceRefs []schema.SourceRef) []schema.SourceRef {
	refs := make([]schema.SourceRef, 0, len(sourceRefs))
	seen := map[string]struct{}{}
	for _, sourceRef := range sourceRefs {
		if _, ok := seen[sourceRef.ID]; ok {
			continue
		}
		seen[sourceRef.ID] = struct{}{}
		refs = append(refs, sourceRef)
	}
	return refs
}

func sourceRefIDs(sourceRefs []schema.SourceRef) []string {
	ids := make([]string, 0, len(sourceRefs))
	seen := map[string]struct{}{}
	for _, sourceRef := range sourceRefs {
		if _, ok := seen[sourceRef.ID]; ok {
			continue
		}
		seen[sourceRef.ID] = struct{}{}
		ids = append(ids, sourceRef.ID)
	}
	return ids
}

func sourceRefDetails(sourceRefs []schema.SourceRef) []map[string]string {
	details := make([]map[string]string, 0, len(sourceRefs))
	for _, sourceRef := range sourceRefs {
		details = append(details, map[string]string{
			"id":        sourceRef.ID,
			"source_id": sourceRef.SourceID,
			"url":       sourceRef.URL,
		})
	}
	return details
}

func (a Adapter) sourceUnavailableEvidence(sourceRef schema.SourceRef, normalized *normalizedMetadata, failureKind string, extra map[string]any) schema.Evidence {
	details := map[string]any{
		"source":       SourceName,
		"failure_kind": failureKind,
	}
	if normalized != nil {
		details["ecosystem"] = normalized.Ecosystem
		details["depsdev_system"] = normalized.System
		details["package_name"] = normalized.Name
		details["version"] = normalized.Version
	}
	for key, value := range extra {
		details[key] = value
	}

	return schema.Evidence{
		Reason: schema.Reason{
			Code:           reasons.SourceUnavailable,
			Severity:       "MEDIUM",
			DecisionEffect: schema.DecisionEffectUnknown,
			Message:        "deps.dev local metadata was unavailable, malformed, or missing required package identity data.",
			SourceRefIDs:   []string{sourceRef.ID},
			Details:        details,
		},
		SourceRef: &sourceRef,
	}
}

func (a Adapter) recordSetSourceRef() schema.SourceRef {
	return a.sourceRef("depsdev-local-record-set", "local-record-set", licenseOrTermsURL)
}

func (a Adapter) localJSONSourceRef(data []byte) schema.SourceRef {
	sum := sha256.Sum256(bytes.TrimSpace(data))
	sourceID := "local-json:" + hex.EncodeToString(sum[:])[:16]
	return a.sourceRef("depsdev-json-"+hex.EncodeToString(sum[:])[:16], sourceID, licenseOrTermsURL)
}

func (a Adapter) versionSourceRef(normalized normalizedMetadata) schema.SourceRef {
	return a.sourceRef(sourceRefID("version", normalized.SourceID), normalized.SourceID, normalized.VersionURL)
}

func (a Adapter) packageSourceRef(normalized normalizedMetadata) schema.SourceRef {
	return a.sourceRef(sourceRefID("package", normalized.PackageID), normalized.PackageID, normalized.PackageURL)
}

func (a Adapter) dependenciesSourceRef(normalized normalizedMetadata) schema.SourceRef {
	sourceID := normalized.SourceID + ":dependencies"
	return a.sourceRef(sourceRefID("dependencies", sourceID), sourceID, dependenciesAPIURL(normalized))
}

func (a Adapter) linkSourceRef(link Link) schema.SourceRef {
	sourceID := "repository:" + canonicalURL(link.URL)
	return a.sourceRef("depsdev-link-"+shortHash(sourceID), sourceID, canonicalURL(link.URL))
}

func (a Adapter) sourceRef(id, sourceID, sourceURL string) schema.SourceRef {
	return schema.SourceRef{
		ID:                  id,
		Source:              SourceName,
		SourceID:            sourceID,
		URL:                 sourceURL,
		RetrievedAt:         a.now().UTC().Format(time.RFC3339),
		TTLSeconds:          a.ttlSeconds,
		LicenseOrTermsURL:   licenseOrTermsURL,
		Attribution:         "Source: deps.dev / Open Source Insights metadata from Google; expected CC-BY-4.0 attribution applies when data is displayed or redistributed",
		AttributionRequired: true,
		Redistribution:      sources.RedistributionUnknown,
		PublicDisplay:       sources.PublicDisplayAllowed,
	}
}

func sourceRefID(kind, value string) string {
	normalized := sourceRefIDReplacer.ReplaceAllString(strings.ToLower(strings.TrimSpace(value)), "-")
	normalized = strings.Trim(normalized, "-")
	if normalized == "" {
		normalized = shortHash(value)
	}
	if len(normalized) > 80 {
		normalized = normalized[:48] + "-" + shortHash(value)
	}
	return "depsdev-" + kind + "-" + normalized
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:])[:16]
}

func versionSourceID(normalized normalizedMetadata) string {
	return fmt.Sprintf("%s:%s@%s", normalized.System, normalized.Name, normalized.Version)
}

func packageSourceID(normalized normalizedMetadata) string {
	return fmt.Sprintf("%s:%s", normalized.System, normalized.Name)
}

func packageAPIURL(normalized normalizedMetadata) string {
	parts := []string{"v3", "systems", normalized.System, "packages", normalized.Name}
	return apiURL(parts, "")
}

func versionAPIURL(normalized normalizedMetadata) string {
	parts := []string{"v3", "systems", normalized.System, "packages", normalized.Name, "versions", normalized.Version}
	return apiURL(parts, "")
}

func dependenciesAPIURL(normalized normalizedMetadata) string {
	parts := []string{"v3", "systems", normalized.System, "packages", normalized.Name, "versions", normalized.Version}
	return apiURL(parts, ":dependencies")
}

func apiURL(parts []string, suffix string) string {
	escaped := make([]string, 0, len(parts))
	for _, part := range parts {
		escaped = append(escaped, escapeURIComponent(part))
	}
	return apiScheme + "://" + apiHost + "/" + strings.Join(escaped, "/") + suffix
}

func purl(ecosystem, name, version string) string {
	typeName := ecosystem
	if ecosystem == "go" {
		typeName = "golang"
	}
	return "pkg:" + typeName + "/" + purlName(ecosystem, name) + "@" + escapeURIComponent(version)
}

func purlName(ecosystem, name string) string {
	if ecosystem == "npm" && strings.HasPrefix(name, "@") {
		namespace, packageName, ok := strings.Cut(name, "/")
		if ok && strings.TrimSpace(packageName) != "" {
			return escapeURIComponent(namespace) + "/" + escapeURIComponent(packageName)
		}
	}
	if ecosystem == "go" {
		return strings.Join(escapePathSegments(name), "/")
	}
	return escapeURIComponent(name)
}

func escapePathSegments(value string) []string {
	parts := strings.Split(value, "/")
	escaped := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		escaped = append(escaped, escapeURIComponent(part))
	}
	return escaped
}

func escapeURIComponent(value string) string {
	return strings.ReplaceAll(url.PathEscape(value), "@", "%40")
}

func normalizeStringList(values []string) []string {
	normalized := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized
}

func compactStrings(values []string) []string {
	compacted := values[:0]
	for _, value := range values {
		if len(compacted) == 0 || compacted[len(compacted)-1] != value {
			compacted = append(compacted, value)
		}
	}
	return compacted
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
