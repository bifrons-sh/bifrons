package main

import (
	"bytes"
	"io"
)

// jsonReader wraps a []byte as an io.Reader; nil value yields a nil reader so
// http.NewRequestWithContext doesn't wrap an empty body into a non-nil Reader.
type jsonReader struct{ data []byte }

func (j *jsonReader) reader() io.Reader {
	if j == nil {
		return nil
	}
	return bytes.NewReader(j.data)
}

// readAll caps the read so an unbounded error body can't eat memory.
func readAll(r io.Reader, limit int) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, int64(limit)))
}
