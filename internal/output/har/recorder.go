// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package har

import (
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"sync"
)

// Recorder streams a single HAR document to an io.Writer. The document header
// is written lazily before the first entry and the closing structure is
// written by Flush or Close, so a crash leaves at most one trailing comma.
// WriteEntry, Flush and Close are safe for concurrent use.
type Recorder struct {
	mu             sync.Mutex
	writer         io.Writer
	creatorVersion string
	headerWritten  bool
	entryCount     int
	finished       bool
	writeErr       error
}

// NewRecorder creates a recorder. An empty creatorVersion becomes "dev".
func NewRecorder(writer io.Writer, creatorVersion string) *Recorder {
	if creatorVersion == "" {
		creatorVersion = "dev"
	}
	return &Recorder{writer: writer, creatorVersion: creatorVersion}
}

// Entries returns the number of entries written so far.
func (r *Recorder) Entries() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.entryCount
}

// WriteEntry appends one complete entry to the archive.
func (r *Recorder) WriteEntry(entry Entry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.finished {
		return stderrors.New("HAR recorder is closed")
	}
	if r.writer == nil {
		return stderrors.New("HAR recorder writer is nil")
	}
	if r.writeErr != nil {
		return r.writeErr
	}

	encoded, err := json.Marshal(entry)
	if err != nil {
		// A marshal failure must not poison the document.
		return fmt.Errorf("marshal HAR entry: %w", err)
	}

	var prefix []byte
	if !r.headerWritten {
		prefix = append(prefix, r.headerLocked()...)
	} else if r.entryCount > 0 {
		prefix = append(prefix, ',')
	}
	prefix = append(prefix, encoded...)

	if _, err = r.writer.Write(prefix); err != nil {
		r.writeErr = err
		return err
	}
	r.entryCount++
	return nil
}

func (r *Recorder) headerLocked() []byte {
	r.headerWritten = true
	creator, _ := json.Marshal(Creator{Name: "ecapture", Version: r.creatorVersion})
	return []byte(fmt.Sprintf("{\"log\":{\"version\":%q,\"creator\":%s,\"pages\":[],\"entries\":[", Version, creator))
}

// Flush terminates the document and flushes the underlying destination.
func (r *Recorder) Flush() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.finishLocked(); err != nil {
		return err
	}
	if flusher, ok := r.writer.(interface{ Flush() error }); ok {
		return flusher.Flush()
	}
	return nil
}

// Close terminates the document and closes the destination when it is a
// closer. Close is idempotent.
func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.finished && r.writeErr != nil {
		return r.writeErr
	}
	finishErr := r.finishLocked()
	var closeErr error
	if closer, ok := r.writer.(io.Closer); ok {
		closeErr = closer.Close()
	}
	return stderrors.Join(finishErr, closeErr)
}

func (r *Recorder) finishLocked() error {
	if r.finished {
		return r.writeErr
	}
	r.finished = true
	if r.writer == nil {
		return nil
	}
	var payload []byte
	if !r.headerWritten {
		payload = append(payload, r.headerLocked()...)
	}
	payload = append(payload, "]}}"...)
	if _, err := r.writer.Write(payload); err != nil {
		r.writeErr = err
		return err
	}
	return r.writeErr
}
