// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

package burpxml

import (
	stderrors "errors"
	"sync"

	"github.com/gojue/ecapture/v2/internal/domain"
	"github.com/gojue/ecapture/v2/internal/output/har"
	"github.com/gojue/ecapture/v2/internal/output/writers"
	"github.com/gojue/ecapture/v2/internal/probe/openssl"
)

// HandlerName is the dispatcher identity of the Burp XML handler.
const HandlerName = "burpxml"

// Handler feeds decrypted OpenSSL TLS payloads through the HAR correlator and
// appends each completed exchange to a Burp XML document. Parse problems are
// swallowed so a malformed HTTP stream never stops the capture pipeline.
type Handler struct {
	mu         sync.Mutex
	writer     writers.ByteSink
	exporter   *Writer
	correlator *har.Correlator
	closed     bool
	closeErr   error
}

// NewHandler wraps sink in an event handler. The handler owns the sink and
// closes it with the document writer.
func NewHandler(sink writers.ByteSink) *Handler {
	exporter := NewWriter(sink)
	return &Handler{
		writer:     sink,
		exporter:   exporter,
		correlator: har.NewCorrelatorFor(exporter),
	}
}

// Supports accepts only OpenSSL TLS data events; the handler is intentionally
// limited to the probe that produces HTTP plaintext in the expected shape.
func (h *Handler) Supports(event domain.Event) bool {
	if event == nil {
		return false
	}
	_, ok := event.(*openssl.Event)
	return ok
}

// Handle never returns a parse error: incomplete streams stay buffered and
// unparseable junk is dropped inside the correlator.
func (h *Handler) Handle(event domain.Event) error {
	tlsEvent, ok := event.(*openssl.Event)
	if !ok {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	h.correlator.Feed(tlsEvent)
	return nil
}

// Name returns the dispatcher identity.
func (h *Handler) Name() string {
	return HandlerName
}

// Writer returns the owned byte sink.
func (h *Handler) Writer() writers.OutputWriter {
	return h.writer
}

// Close finalizes the XML document and closes the sink. Close is idempotent.
func (h *Handler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return h.closeErr
	}
	h.closed = true
	h.closeErr = stderrors.Join(h.exporter.Close())
	return h.closeErr
}
