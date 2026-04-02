package output

import (
	"encoding/json"
	"io"
	"sync"

	"github.com/nextinfra/ja4finger/fingerprint"
)

type JSONLEmitter struct {
	mu      sync.Mutex
	encoder *json.Encoder
}

func NewJSONLEmitter(w io.Writer) *JSONLEmitter {
	return &JSONLEmitter{encoder: json.NewEncoder(w)}
}

func (e *JSONLEmitter) Emit(result *fingerprint.Result) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.encoder.Encode(result)
}
