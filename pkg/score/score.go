package score

import "github.com/attach-dev/attach-open-score/pkg/schema"

type Request struct {
	Package  schema.PackageIdentity
	Evidence []Evidence
	Mode     string
}

type Evidence struct {
	Reason    schema.Reason
	SourceRef *schema.SourceRef
}

type Result = schema.Verdict
