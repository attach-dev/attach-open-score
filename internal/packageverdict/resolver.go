package packageverdict

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/attach-dev/attach-open-score/internal/verdictdb"
	"github.com/attach-dev/attach-open-score/pkg/reasons"
	"github.com/attach-dev/attach-open-score/pkg/schema"
	"github.com/attach-dev/attach-open-score/pkg/score"
	"github.com/attach-dev/attach-open-score/pkg/sources/osv"
)

type Request struct {
	Ecosystem     string
	Name          string
	Version       string
	PolicyProfile string
	Refresh       bool
}

type Resolver struct {
	db         *verdictdb.DB
	httpClient osv.HTTPClient
	now        func() time.Time
}

func New(db *verdictdb.DB) *Resolver {
	if db == nil {
		db = verdictdb.New("")
	}
	return &Resolver{
		db: db,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		now: time.Now,
	}
}

func (r *Resolver) Resolve(ctx context.Context, request Request) (schema.Verdict, bool, error) {
	profile := normalizeProfile(request.PolicyProfile)
	pkg, err := packageIdentity(request)
	if err != nil {
		return schema.Verdict{}, false, err
	}

	key := verdictdb.NormalizeKey(pkg.Ecosystem, pkg.Name, pkg.Version, profile)
	if !request.Refresh {
		if cached, ok, err := r.db.Get(key); err != nil {
			return schema.Verdict{}, false, err
		} else if ok {
			return cached, true, nil
		}
	}

	engine, err := score.NewEngine(score.Options{
		Now:           r.now,
		PolicyProfile: profile,
	})
	if err != nil {
		return schema.Verdict{}, false, err
	}

	evidence, err := r.evidence(ctx, pkg)
	if err != nil {
		return schema.Verdict{}, false, err
	}
	verdict, err := engine.Evaluate(schema.Request{Package: pkg, Evidence: evidence})
	if err != nil {
		return schema.Verdict{}, false, err
	}
	if err := r.db.Put(key, verdict); err != nil {
		return schema.Verdict{}, false, err
	}
	return verdict, false, nil
}

func (r *Resolver) evidence(ctx context.Context, pkg schema.PackageIdentity) ([]schema.Evidence, error) {
	client, err := osv.NewClient(osv.Options{
		HTTPClient: r.httpClient,
		Now:        r.now,
	})
	if err != nil {
		return nil, err
	}
	evidence, err := client.EvidenceForPackage(ctx, pkg)
	if err != nil {
		return []schema.Evidence{unsupportedEcosystemEvidence(pkg)}, nil
	}
	return evidence, nil
}

func packageIdentity(request Request) (schema.PackageIdentity, error) {
	ecosystem := normalizeEcosystem(request.Ecosystem)
	name := strings.TrimSpace(request.Name)
	version := strings.TrimSpace(request.Version)
	if ecosystem == "" {
		return schema.PackageIdentity{}, fmt.Errorf("ecosystem is required")
	}
	if name == "" {
		return schema.PackageIdentity{}, fmt.Errorf("name is required")
	}
	if version == "" {
		return schema.PackageIdentity{}, fmt.Errorf("version is required")
	}
	return schema.PackageIdentity{
		Ecosystem: ecosystem,
		Name:      name,
		Version:   version,
		PURL:      purl(ecosystem, name, version),
		Resolved:  true,
	}, nil
}

func normalizeProfile(profile string) string {
	switch strings.TrimSpace(profile) {
	case "", "default":
		return score.ProfileLocalDevDefault
	default:
		return strings.TrimSpace(profile)
	}
}

func normalizeEcosystem(ecosystem string) string {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "pnpm", "yarn":
		return "npm"
	case "python":
		return "pypi"
	case "golang":
		return "go"
	case "cargo", "rust", "crates.io":
		return "crates"
	default:
		return strings.ToLower(strings.TrimSpace(ecosystem))
	}
}

func purl(ecosystem, name, version string) string {
	purlType := ecosystem
	if ecosystem == "go" {
		purlType = "golang"
	}
	return fmt.Sprintf("pkg:%s/%s@%s", purlType, name, version)
}

func unsupportedEcosystemEvidence(pkg schema.PackageIdentity) schema.Evidence {
	return schema.Evidence{
		Reason: schema.Reason{
			Code:           reasons.UnsupportedEcosystem,
			Severity:       "MEDIUM",
			DecisionEffect: schema.DecisionEffectUnknown,
			Message:        fmt.Sprintf("Attach Open Score does not yet have live evidence collection for ecosystem %s.", pkg.Ecosystem),
		},
	}
}
