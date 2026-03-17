package mapping

import (
	_ "embed"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/letzcode/k8s-eu-audit/internal/model"
)

//go:embed nis2.yaml
var nis2YAML []byte

//go:embed dora.yaml
var doraYAML []byte

var embeddedFrameworks = map[string][]byte{
	"nis2": nis2YAML,
	"dora": doraYAML,
}

// Load reads a framework definition from embedded YAML.
func Load(id string) (model.Framework, error) {
	data, ok := embeddedFrameworks[id]
	if !ok {
		return model.Framework{}, fmt.Errorf("unknown framework %q — available: nis2, dora", id)
	}
	var fw model.Framework
	if err := yaml.Unmarshal(data, &fw); err != nil {
		return model.Framework{}, fmt.Errorf("parse framework %q: %w", id, err)
	}
	return fw, nil
}

// AvailableIDs returns all registered framework IDs.
func AvailableIDs() ([]string, error) {
	ids := make([]string, 0, len(embeddedFrameworks))
	for id := range embeddedFrameworks {
		ids = append(ids, id)
	}
	return ids, nil
}
