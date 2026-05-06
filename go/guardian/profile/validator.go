package profile

import (
	"encoding/json"
	"errors"
)

var knownPPPKeys = map[string]struct{}{
	"concurrent": {},
	"key":        {},
	"tcp":        {},
	"udp":        {},
	"mux":        {},
	"websocket":  {},
	"server":     {},
	"client":     {},
}

func validateProfile(content []byte) error {
	var data any
	if err := json.Unmarshal(content, &data); err != nil {
		return err
	}
	if !containsKnownKey(data) {
		return errors.New("profile JSON does not contain a known ppp key")
	}
	return nil
}

func containsKnownKey(v any) bool {
	switch val := v.(type) {
	case map[string]any:
		for k, inner := range val {
			if _, ok := knownPPPKeys[k]; ok {
				return true
			}
			if containsKnownKey(inner) {
				return true
			}
		}
	case []any:
		for _, item := range val {
			if containsKnownKey(item) {
				return true
			}
		}
	}
	return false
}
