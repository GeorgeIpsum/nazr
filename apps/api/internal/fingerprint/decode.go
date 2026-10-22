package fingerprint

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Components is a decoded component tree. Leaves are string, bool, nil,
// json.Number, float64 or []any; branches are map[string]any.
type Components = map[string]any

var (
	// ErrTooLarge is returned by Decode when the body exceeds the limit.
	ErrTooLarge = errors.New("fingerprint: body too large")
	// ErrNotObject is returned by Decode when the top-level value is not an object.
	ErrNotObject = errors.New("fingerprint: top-level JSON value is not an object")
)

// Decode reads one JSON object from r, reading at most limit bytes. Numbers
// are kept as json.Number so their text is preserved.
func Decode(r io.Reader, limit int64) (Components, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, ErrTooLarge
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("fingerprint: unexpected data after top-level value")
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, ErrNotObject
	}
	return m, nil
}
