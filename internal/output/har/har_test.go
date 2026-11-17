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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gojue/ecapture/v2/internal/domain"
	"github.com/gojue/ecapture/v2/internal/output/writers"
	"github.com/gojue/ecapture/v2/internal/probe/openssl"
)

type bufferSink struct {
	bytes.Buffer
}

func (b *bufferSink) Name() string { return "buffer" }
func (b *bufferSink) Flush() error { return nil }
func (b *bufferSink) Close() error { return nil }

func newTestHandler() (*Handler, *bufferSink) {
	sink := &bufferSink{}
	return NewHandler(sink, "test-version"), sink
}

func tlsEvent(pid, fd uint32, dataType int64, payload []byte) *openssl.Event {
	event := &openssl.Event{
		DataType: dataType,
		Pid:      pid,
		Fd:       fd,
		Tuple:    "10.1.1.5:54321-93.184.216.34:443",
	}
	copy(event.Data[:], payload)
	event.DataLen = int32(len(payload))
	return event
}

func feed(t *testing.T, handler *Handler, pid, fd uint32, dataType int64, payload string) {
	t.Helper()
	if err := handler.Handle(tlsEvent(pid, fd, dataType, []byte(payload))); err != nil {
		t.Fatalf("Handle() error: %v", err)
	}
}

func closeAndParse(t *testing.T, handler *Handler, sink *bufferSink) Log {
	t.Helper()
	if err := handler.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}
	var document HAR
	if err := json.Unmarshal(sink.Bytes(), &document); err != nil {
		t.Fatalf("HAR document is not valid JSON: %v\n%s", err, sink.String())
	}
	if document.Log.Version != Version {
		t.Fatalf("HAR version = %q, want %q", document.Log.Version, Version)
	}
	if document.Log.Creator.Name != "ecapture" || document.Log.Creator.Version != "test-version" {
		t.Fatalf("unexpected creator: %#v", document.Log.Creator)
	}
	if document.Log.Pages == nil || len(document.Log.Pages) != 0 {
		t.Fatalf("pages = %#v, want empty array", document.Log.Pages)
	}
	if document.Log.Entries == nil {
		t.Fatal("entries = nil, want an array")
	}
	return document.Log
}

func TestHARScenarios(t *testing.T) {
	simpleRequest := []byte("GET /index.html?x=1&y=2 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: har-test\r\nAccept: */*\r\n\r\n")
	simpleResponse := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello")
	binaryResponse := append([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\n\r\n"),
		[]byte{0xff, 0xfe, 0x00, 0x01}...)
	pipelineRequests := []byte("GET /one HTTP/1.1\r\nHost: example.com\r\n\r\n" +
		"POST /two HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabc")
	pipelineResponses := []byte("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na" +
		"HTTP/1.1 201 Created\r\nContent-Length: 1\r\n\r\nb")
	tlsNoise := []byte{0x16, 0x03, 0x01, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x2b, 0x03, 0x03}
	tlsReadNoise := []byte{0x17, 0x03, 0x03, 0x00, 0x20}
	noisyResponse := append(append([]byte{}, tlsReadNoise...), []byte("HTTP/1.1 204 No Content\r\n\r\n")...)

	tests := []struct {
		name        string
		writes      [][]byte
		reads       [][]byte
		wantEntries int
		check       func(t *testing.T, document Log)
	}{
		{
			name:        "simple GET and 200 response",
			writes:      [][]byte{simpleRequest},
			reads:       [][]byte{simpleResponse},
			wantEntries: 1,
			check: func(t *testing.T, document Log) {
				entry := document.Entries[0]
				if entry.Request.Method != "GET" {
					t.Errorf("method = %q", entry.Request.Method)
				}
				if entry.Request.URL != "https://example.com/index.html?x=1&y=2" {
					t.Errorf("url = %q", entry.Request.URL)
				}
				if entry.Request.HTTPVersion != "HTTP/1.1" {
					t.Errorf("httpVersion = %q", entry.Request.HTTPVersion)
				}
				if len(entry.Request.QueryString) != 2 ||
					entry.Request.QueryString[0].Name != "x" || entry.Request.QueryString[1].Name != "y" {
					t.Errorf("queryString = %#v", entry.Request.QueryString)
				}
				if len(entry.Request.Headers) != 3 || entry.Request.Headers[1].Name != "User-Agent" {
					t.Errorf("headers = %#v", entry.Request.Headers)
				}
				if entry.Request.HeadersSize <= 0 || entry.Request.BodySize != 0 {
					t.Errorf("request sizes = %d/%d", entry.Request.HeadersSize, entry.Request.BodySize)
				}
				if entry.Response.Status != 200 || entry.Response.StatusText != "OK" {
					t.Errorf("response = %d %q", entry.Response.Status, entry.Response.StatusText)
				}
				if entry.Response.Content.Text != "hello" || entry.Response.Content.Size != 5 {
					t.Errorf("content = %#v", entry.Response.Content)
				}
				if entry.Response.Content.MimeType != "text/plain" {
					t.Errorf("mimeType = %q", entry.Response.Content.MimeType)
				}
				if entry.Response.Content.Encoding != "" {
					t.Errorf("encoding = %q, want empty", entry.Response.Content.Encoding)
				}
				if entry.Response.BodySize != 5 || entry.Response.HeadersSize <= 0 {
					t.Errorf("response sizes = %d/%d", entry.Response.BodySize, entry.Response.HeadersSize)
				}
				if entry.Time < 0 {
					t.Errorf("time = %v", entry.Time)
				}
				if _, err := time.Parse("2006-01-02T15:04:05.000-07:00", entry.StartedDateTime); err != nil {
					t.Errorf("startedDateTime %q: %v", entry.StartedDateTime, err)
				}
				if entry.ServerIPAddress != "93.184.216.34" || entry.Connection != "93.184.216.34:443" {
					t.Errorf("server = %q connection = %q", entry.ServerIPAddress, entry.Connection)
				}
			},
		},
		{
			name:        "chunked response",
			writes:      [][]byte{[]byte("GET /chunked HTTP/1.1\r\nHost: example.com\r\n\r\n")},
			reads:       [][]byte{[]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")},
			wantEntries: 1,
			check: func(t *testing.T, document Log) {
				content := document.Entries[0].Response.Content
				if content.Text != "hello world" || content.Size != 11 {
					t.Fatalf("content = %#v", content)
				}
				if content.Encoding != "" {
					t.Fatalf("encoding = %q", content.Encoding)
				}
			},
		},
		{
			name:        "binary response uses base64",
			writes:      [][]byte{[]byte("GET /bin HTTP/1.1\r\nHost: example.com\r\n\r\n")},
			reads:       [][]byte{binaryResponse},
			wantEntries: 1,
			check: func(t *testing.T, document Log) {
				content := document.Entries[0].Response.Content
				if content.Encoding != "base64" {
					t.Fatalf("encoding = %q, want base64", content.Encoding)
				}
				decoded, err := base64.StdEncoding.DecodeString(content.Text)
				if err != nil {
					t.Fatalf("base64 decode: %v", err)
				}
				if !bytes.Equal(decoded, []byte{0xff, 0xfe, 0x00, 0x01}) {
					t.Fatalf("decoded = %x", decoded)
				}
				if content.Size != 4 {
					t.Fatalf("size = %d, want 4", content.Size)
				}
			},
		},
		{
			name:        "pipelined keep-alive requests",
			writes:      [][]byte{pipelineRequests},
			reads:       [][]byte{pipelineResponses},
			wantEntries: 2,
			check: func(t *testing.T, document Log) {
				if len(document.Entries) != 2 {
					t.Fatalf("entries = %d, want 2", len(document.Entries))
				}
				first, second := document.Entries[0], document.Entries[1]
				if first.Request.URL != "https://example.com/one" || first.Response.Status != 200 || first.Response.Content.Text != "a" {
					t.Fatalf("first entry = %#v", first)
				}
				if second.Request.URL != "https://example.com/two" || second.Request.Method != "POST" ||
					second.Response.Status != 201 || second.Response.Content.Text != "b" {
					t.Fatalf("second entry = %#v", second)
				}
				if second.Request.PostData == nil || second.Request.PostData.Text != "abc" || second.Request.BodySize != 3 {
					t.Fatalf("post data = %#v size=%d", second.Request.PostData, second.Request.BodySize)
				}
			},
		},
		{
			name:        "TLS noise is ignored",
			writes:      [][]byte{tlsNoise, []byte("GET /after-noise HTTP/1.1\r\nHost: example.com\r\n\r\n")},
			reads:       [][]byte{noisyResponse},
			wantEntries: 1,
			check: func(t *testing.T, document Log) {
				if document.Entries[0].Request.URL != "https://example.com/after-noise" {
					t.Fatalf("url = %q", document.Entries[0].Request.URL)
				}
				if document.Entries[0].Response.Status != 204 {
					t.Fatalf("status = %d", document.Entries[0].Response.Status)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, sink := newTestHandler()
			for _, payload := range test.writes {
				_ = handler.Handle(tlsEvent(1, 3, openssl.DataTypeWrite, payload))
			}
			for _, payload := range test.reads {
				_ = handler.Handle(tlsEvent(1, 3, openssl.DataTypeRead, payload))
			}
			document := closeAndParse(t, handler, sink)
			if len(document.Entries) != test.wantEntries {
				t.Fatalf("entries = %d, want %d\n%s", len(document.Entries), test.wantEntries, sink.String())
			}
			test.check(t, document)
		})
	}
}

func TestEmptyRecorderWritesValidDocument(t *testing.T) {
	handler, sink := newTestHandler()
	document := closeAndParse(t, handler, sink)
	if len(document.Entries) != 0 {
		t.Fatalf("entries = %d, want 0", len(document.Entries))
	}
	if document.Pages == nil {
		t.Fatal("pages = nil")
	}
}

func TestHandlerSupportsOnlyOpenSSLEvents(t *testing.T) {
	handler, _ := newTestHandler()
	if handler.Supports(nil) {
		t.Fatal("Supports(nil) = true")
	}
	if handler.Supports(&foreignEvent{}) {
		t.Fatal("Supports(foreign) = true")
	}
	if !handler.Supports(&openssl.Event{}) {
		t.Fatal("Supports(*openssl.Event) = false")
	}
	if handler.Name() != HandlerName || handler.Writer() == nil {
		t.Fatalf("handler identity = %q writer=%v", handler.Name(), handler.Writer())
	}
}

func TestPartialMessagesAcrossEvents(t *testing.T) {
	handler, sink := newTestHandler()
	feed(t, handler, 77, 3, openssl.DataTypeWrite, "GET /spl")
	feed(t, handler, 77, 3, openssl.DataTypeWrite, "it HTTP/1.1\r\nHost: exa")
	feed(t, handler, 77, 3, openssl.DataTypeWrite, "mple.com\r\n\r\n")
	feed(t, handler, 77, 3, openssl.DataTypeRead, "HTTP/1.1 200 OK\r\nContent-Len")
	feed(t, handler, 77, 3, openssl.DataTypeRead, "gth: 5\r\n\r\nsp")
	feed(t, handler, 77, 3, openssl.DataTypeRead, "lit")

	document := closeAndParse(t, handler, sink)
	if len(document.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(document.Entries))
	}
	if document.Entries[0].Request.URL != "https://example.com/split" ||
		document.Entries[0].Response.Content.Text != "split" {
		t.Fatalf("entry = %#v", document.Entries[0])
	}
}

func TestAppendBodyTruncatesAtLimit(t *testing.T) {
	var body []byte
	truncated := false
	appendBody(&body, bytes.Repeat([]byte("a"), maxBodyText+123), &truncated)
	if len(body) != maxBodyText || !truncated {
		t.Fatalf("len = %d truncated = %v", len(body), truncated)
	}
	encoded := encodeBody(body, truncated)
	if encoded.comment == "" {
		t.Fatal("truncated body lacks a comment marker")
	}
}

func TestConcurrentStreams(t *testing.T) {
	handler, sink := newTestHandler()
	const streams = 32
	var wait sync.WaitGroup
	for i := 0; i < streams; i++ {
		pid := uint32(i + 1)
		wait.Add(1)
		go func() {
			defer wait.Done()
			_ = handler.Handle(tlsEvent(pid, 1, openssl.DataTypeWrite,
				[]byte(fmt.Sprintf("GET /stream/%d HTTP/1.1\r\nHost: example.com\r\n\r\n", pid))))
			_ = handler.Handle(tlsEvent(pid, 1, openssl.DataTypeRead,
				[]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")))
		}()
	}
	wait.Wait()

	document := closeAndParse(t, handler, sink)
	if len(document.Entries) != streams {
		t.Fatalf("entries = %d, want %d", len(document.Entries), streams)
	}
}

func TestFileSinkProducesValidDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.har")
	sink, err := writers.NewWriterFactory().CreateEventSink(writers.EventSinkOptions{
		Address: path,
		Format:  writers.EventFormatHar,
	})
	if err != nil {
		t.Fatalf("CreateEventSink() error: %v", err)
	}
	handler := NewHandler(sink, "file-test")
	feed(t, handler, 3, 8, openssl.DataTypeWrite, "GET /file HTTP/1.1\r\nHost: example.com\r\n\r\n")
	feed(t, handler, 3, 8, openssl.DataTypeRead, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	if err := handler.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document HAR
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("file is not valid HAR: %v\n%s", err, data)
	}
	if len(document.Log.Entries) != 1 || document.Log.Entries[0].Request.URL != "https://example.com/file" {
		t.Fatalf("entries = %#v", document.Log.Entries)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %o, want 600", info.Mode().Perm())
	}
}

type foreignEvent struct{}

func (e *foreignEvent) DecodeFromBytes([]byte) error { return nil }
func (e *foreignEvent) String() string               { return "" }
func (e *foreignEvent) StringHex() string            { return "" }
func (e *foreignEvent) Clone() domain.Event          { return &foreignEvent{} }
func (e *foreignEvent) Type() domain.EventType       { return domain.EventTypeOutput }
func (e *foreignEvent) UUID() string                 { return "foreign" }
func (e *foreignEvent) Validate() error              { return nil }
