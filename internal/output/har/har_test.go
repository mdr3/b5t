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
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gojue/ecapture/v2/internal/domain"
	"github.com/gojue/ecapture/v2/internal/output/writers"
	"github.com/gojue/ecapture/v2/internal/probe/openssl"
	"golang.org/x/net/http2/hpack"
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

// h2TestEncoder keeps one HPACK encoder alive per connection direction so
// dynamic table references stay valid across header blocks.
type h2TestEncoder struct {
	buf bytes.Buffer
	enc *hpack.Encoder
}

func newH2TestEncoder() *h2TestEncoder {
	e := &h2TestEncoder{}
	e.enc = hpack.NewEncoder(&e.buf)
	return e
}

func (e *h2TestEncoder) block(t *testing.T, fields ...hpack.HeaderField) []byte {
	t.Helper()
	e.buf.Reset()
	for _, field := range fields {
		if err := e.enc.WriteField(field); err != nil {
			t.Fatalf("hpack encode %q: %v", field.Name, err)
		}
	}
	return append([]byte(nil), e.buf.Bytes()...)
}

func h2Frame(frameType, flags byte, streamID uint32, payload []byte) []byte {
	frame := make([]byte, h2FrameHeaderLen, h2FrameHeaderLen+len(payload))
	frame[0] = byte(len(payload) >> 16)
	frame[1] = byte(len(payload) >> 8)
	frame[2] = byte(len(payload))
	frame[3] = frameType
	frame[4] = flags
	binary.BigEndian.PutUint32(frame[5:], streamID)
	return append(frame, payload...)
}

func h2RequestFields(method, path, authority string) []hpack.HeaderField {
	return []hpack.HeaderField{
		{Name: ":method", Value: method},
		{Name: ":authority", Value: authority},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: path},
		{Name: "user-agent", Value: "har-h2-test"},
		{Name: "accept", Value: "*/*"},
	}
}

func h2ResponseFields(status, contentType string) []hpack.HeaderField {
	fields := []hpack.HeaderField{{Name: ":status", Value: status}}
	if contentType != "" {
		fields = append(fields, hpack.HeaderField{Name: "content-type", Value: contentType})
	}
	return fields
}

func feedBytes(t *testing.T, handler *Handler, dataType int64, payload []byte) {
	t.Helper()
	if err := handler.Handle(tlsEvent(11, 22, dataType, payload)); err != nil {
		t.Fatalf("Handle() error: %v", err)
	}
}

// feedH2 starts an h2 capture on a fresh handler and returns its encoders.
func feedH2(t *testing.T, handler *Handler) (*h2TestEncoder, *h2TestEncoder) {
	t.Helper()
	feedBytes(t, handler, openssl.DataTypeWrite, []byte(http2Preface))
	return newH2TestEncoder(), newH2TestEncoder()
}

func TestH2RequestResponse(t *testing.T) {
	handler, sink := newTestHandler()
	client, server := feedH2(t, handler)

	feedBytes(t, handler, openssl.DataTypeWrite,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders, 1, client.block(t, h2RequestFields("POST", "/upload?x=1&y=2", "example.com")...)))
	feedBytes(t, handler, openssl.DataTypeWrite, h2Frame(h2FrameData, 0, 1, []byte("payload")))
	feedBytes(t, handler, openssl.DataTypeWrite, h2Frame(h2FrameData, h2FlagEndStream, 1, nil))
	feedBytes(t, handler, openssl.DataTypeRead,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders, 1, server.block(t, h2ResponseFields("200", "text/plain")...)))
	feedBytes(t, handler, openssl.DataTypeRead, h2Frame(h2FrameData, h2FlagEndStream, 1, []byte("ok")))

	document := closeAndParse(t, handler, sink)
	if len(document.Entries) != 1 {
		t.Fatalf("entries = %d, want 1\n%s", len(document.Entries), sink.String())
	}
	entry := document.Entries[0]
	if entry.Request.HTTPVersion != http2Version || entry.Response.HTTPVersion != http2Version {
		t.Fatalf("httpVersion = %q/%q", entry.Request.HTTPVersion, entry.Response.HTTPVersion)
	}
	if entry.Request.Method != "POST" {
		t.Errorf("method = %q", entry.Request.Method)
	}
	if entry.Request.URL != "https://example.com/upload?x=1&y=2" {
		t.Errorf("url = %q", entry.Request.URL)
	}
	if len(entry.Request.QueryString) != 2 || entry.Request.QueryString[0].Name != "x" {
		t.Errorf("queryString = %#v", entry.Request.QueryString)
	}
	if entry.Request.PostData == nil || entry.Request.PostData.Text != "payload" || entry.Request.BodySize != 7 {
		t.Errorf("request body = %#v size=%d", entry.Request.PostData, entry.Request.BodySize)
	}
	if entry.Response.Status != 200 || entry.Response.StatusText != "" {
		t.Errorf("response = %d %q", entry.Response.Status, entry.Response.StatusText)
	}
	if entry.Request.HeadersSize != -1 || entry.Response.HeadersSize != -1 {
		t.Errorf("headersSize = %d/%d, want -1 for h2", entry.Request.HeadersSize, entry.Response.HeadersSize)
	}
	if entry.StreamID != 1 {
		t.Errorf("_streamId = %d, want 1", entry.StreamID)
	}
	pseudoOrder := []string{":method", ":authority", ":scheme", ":path"}
	if len(entry.Request.Headers) < len(pseudoOrder) {
		t.Fatalf("request headers = %#v", entry.Request.Headers)
	}
	for i, want := range pseudoOrder {
		if entry.Request.Headers[i].Name != want {
			t.Errorf("request header[%d] = %q, want %q", i, entry.Request.Headers[i].Name, want)
		}
	}
	for _, header := range entry.Request.Headers {
		if header.Name != strings.ToLower(header.Name) {
			t.Errorf("header %q not lowercase", header.Name)
		}
	}
	if entry.Response.Content.Text != "ok" || entry.Response.Content.Size != 2 {
		t.Errorf("content = %#v", entry.Response.Content)
	}
	if entry.Response.Content.MimeType != "text/plain" {
		t.Errorf("mimeType = %q", entry.Response.Content.MimeType)
	}
	if len(entry.Response.Headers) != 2 || entry.Response.Headers[0].Name != ":status" ||
		entry.Response.Headers[1].Name != "content-type" {
		t.Errorf("response headers = %#v", entry.Response.Headers)
	}
	pseudo := false
	for _, header := range entry.Request.Headers {
		if header.Name == ":path" && header.Value == "/upload?x=1&y=2" {
			pseudo = true
		}
	}
	if !pseudo {
		t.Errorf("pseudo-headers missing from request headers: %#v", entry.Request.Headers)
	}
	if !strings.HasSuffix(entry.Request.URL, "/upload?x=1&y=2") {
		t.Errorf("url = %q", entry.Request.URL)
	}
}

func TestH2HuffmanAndIncrementalIndexing(t *testing.T) {
	handler, sink := newTestHandler()
	client, server := feedH2(t, handler)

	huffmanValue := strings.Repeat("huffman-", 12)
	requestFields := append(h2RequestFields("GET", "/huffman", "example.com"),
		hpack.HeaderField{Name: "x-literal-header", Value: huffmanValue})
	requestBlock := client.block(t, requestFields...)
	if bytes.Contains(requestBlock, []byte(huffmanValue)) {
		t.Fatalf("test block is not huffman encoded")
	}
	feedBytes(t, handler, openssl.DataTypeWrite,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, requestBlock))
	feedBytes(t, handler, openssl.DataTypeRead,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1,
			server.block(t, h2ResponseFields("204", "")...)))

	document := closeAndParse(t, handler, sink)
	if len(document.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(document.Entries))
	}
	value := ""
	for _, header := range document.Entries[0].Request.Headers {
		if header.Name == "x-literal-header" {
			value = header.Value
		}
	}
	if value != huffmanValue {
		t.Fatalf("decoded header = %q, want %q", value, huffmanValue)
	}
	if document.Entries[0].Request.URL != "https://example.com/huffman" {
		t.Fatalf("url = %q", document.Entries[0].Request.URL)
	}
}

func TestH2MultiplexedStreams(t *testing.T) {
	handler, sink := newTestHandler()
	client, server := feedH2(t, handler)

	feedBytes(t, handler, openssl.DataTypeWrite,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, client.block(t, h2RequestFields("GET", "/one", "example.com")...)))
	feedBytes(t, handler, openssl.DataTypeWrite,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 3, client.block(t, h2RequestFields("GET", "/three", "example.com")...)))
	feedBytes(t, handler, openssl.DataTypeRead,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders, 3, server.block(t, h2ResponseFields("200", "text/plain")...)))
	feedBytes(t, handler, openssl.DataTypeRead, h2Frame(h2FrameData, 0, 1, []byte("one-")))
	feedBytes(t, handler, openssl.DataTypeRead, h2Frame(h2FrameData, h2FlagEndStream, 3, []byte("three")))
	feedBytes(t, handler, openssl.DataTypeRead,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders, 1, server.block(t, h2ResponseFields("404", "text/plain")...)))
	feedBytes(t, handler, openssl.DataTypeRead, h2Frame(h2FrameData, h2FlagEndStream, 1, []byte("one")))

	document := closeAndParse(t, handler, sink)
	if len(document.Entries) != 2 {
		t.Fatalf("entries = %d, want 2\n%s", len(document.Entries), sink.String())
	}
	byPath := map[string]Entry{}
	for _, entry := range document.Entries {
		byPath[entry.Request.URL] = entry
	}
	first, ok := byPath["https://example.com/one"]
	if !ok {
		t.Fatalf("missing /one entry: %#v", byPath)
	}
	second, ok := byPath["https://example.com/three"]
	if !ok {
		t.Fatalf("missing /three entry: %#v", byPath)
	}
	if first.Response.Status != 404 || first.Response.Content.Text != "one-one" {
		t.Fatalf("first = %#v", first.Response)
	}
	if second.Response.Status != 200 || second.Response.Content.Text != "three" {
		t.Fatalf("second = %#v", second.Response)
	}
}

func TestH2ContinuationFrames(t *testing.T) {
	handler, sink := newTestHandler()
	client, server := feedH2(t, handler)

	block := client.block(t, h2RequestFields("GET", "/continued", "example.com")...)
	split := len(block) / 2
	feedBytes(t, handler, openssl.DataTypeWrite,
		h2Frame(h2FrameHeaders, h2FlagEndStream, 1, block[:split]))
	feedBytes(t, handler, openssl.DataTypeWrite, h2Frame(h2FrameContinuation, 0, 1, block[split:split+3]))
	feedBytes(t, handler, openssl.DataTypeWrite,
		h2Frame(h2FrameContinuation, h2FlagEndHeaders, 1, block[split+3:]))
	feedBytes(t, handler, openssl.DataTypeRead,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, server.block(t, h2ResponseFields("200", "text/plain")...)))

	document := closeAndParse(t, handler, sink)
	if len(document.Entries) != 1 {
		t.Fatalf("entries = %d, want 1\n%s", len(document.Entries), sink.String())
	}
	if document.Entries[0].Request.URL != "https://example.com/continued" {
		t.Fatalf("url = %q", document.Entries[0].Request.URL)
	}
}

func TestH2PaddedData(t *testing.T) {
	handler, sink := newTestHandler()
	client, server := feedH2(t, handler)

	feedBytes(t, handler, openssl.DataTypeWrite,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, client.block(t, h2RequestFields("GET", "/padded", "example.com")...)))
	feedBytes(t, handler, openssl.DataTypeRead,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders, 1, server.block(t, h2ResponseFields("200", "text/plain")...)))
	padded := append([]byte{3}, []byte("abc")...)
	padded = append(padded, 0, 0, 0)
	feedBytes(t, handler, openssl.DataTypeRead, h2Frame(h2FrameData, h2FlagPadded|h2FlagEndStream, 1, padded))

	document := closeAndParse(t, handler, sink)
	if len(document.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(document.Entries))
	}
	content := document.Entries[0].Response.Content
	if content.Text != "abc" || content.Size != 3 {
		t.Fatalf("content = %#v", content)
	}
}

func TestH2ResetStreamKeepsPartialEntry(t *testing.T) {
	handler, sink := newTestHandler()
	client, server := feedH2(t, handler)

	feedBytes(t, handler, openssl.DataTypeWrite,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders, 1, client.block(t, h2RequestFields("POST", "/reset", "example.com")...)))
	feedBytes(t, handler, openssl.DataTypeRead,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders, 1, server.block(t, h2ResponseFields("200", "text/plain")...)))
	feedBytes(t, handler, openssl.DataTypeRead, h2Frame(h2FrameData, 0, 1, []byte("par")))
	feedBytes(t, handler, openssl.DataTypeRead, h2Frame(h2FrameRSTStream, 0, 1, []byte{0, 0, 0, 8}))

	document := closeAndParse(t, handler, sink)
	if len(document.Entries) != 1 {
		t.Fatalf("entries = %d, want 1\n%s", len(document.Entries), sink.String())
	}
	entry := document.Entries[0]
	if entry.Request.URL != "https://example.com/reset" || entry.Response.Status != 200 {
		t.Fatalf("entry = %#v", entry)
	}
	if entry.Response.Content.Text != "par" || entry.Response.Content.Size != 3 {
		t.Fatalf("content = %#v", entry.Response.Content)
	}
}

func TestH2BinaryBodyUsesBase64(t *testing.T) {
	handler, sink := newTestHandler()
	client, server := feedH2(t, handler)

	feedBytes(t, handler, openssl.DataTypeWrite,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, client.block(t, h2RequestFields("GET", "/binary", "example.com")...)))
	binaryBody := []byte{0xff, 0xfe, 0x00, 0x01}
	feedBytes(t, handler, openssl.DataTypeRead,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders, 1, server.block(t, h2ResponseFields("200", "application/octet-stream")...)))
	feedBytes(t, handler, openssl.DataTypeRead, h2Frame(h2FrameData, h2FlagEndStream, 1, binaryBody))

	document := closeAndParse(t, handler, sink)
	content := document.Entries[0].Response.Content
	if content.Encoding != "base64" {
		t.Fatalf("encoding = %q", content.Encoding)
	}
	decoded, err := base64.StdEncoding.DecodeString(content.Text)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if !bytes.Equal(decoded, binaryBody) || content.Size != int64(len(binaryBody)) {
		t.Fatalf("decoded = %x size = %d", decoded, content.Size)
	}
	if content.MimeType != "application/octet-stream" {
		t.Fatalf("mimeType = %q", content.MimeType)
	}
}

func TestH2PrefaceAndFramesAcrossEvents(t *testing.T) {
	handler, sink := newTestHandler()
	client, server := feedH2(t, handler)

	block := client.block(t, h2RequestFields("GET", "/split", "example.com")...)
	frame := h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, block)
	feedBytes(t, handler, openssl.DataTypeWrite, frame[:7])
	feedBytes(t, handler, openssl.DataTypeWrite, frame[7:12])
	feedBytes(t, handler, openssl.DataTypeWrite, frame[12:])
	feedBytes(t, handler, openssl.DataTypeRead,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, server.block(t, h2ResponseFields("200", "text/plain")...)))

	document := closeAndParse(t, handler, sink)
	if len(document.Entries) != 1 || document.Entries[0].Request.URL != "https://example.com/split" {
		t.Fatalf("entries = %#v", document.Entries)
	}
}

func TestH2HPACKErrorKeepsPipeline(t *testing.T) {
	handler, sink := newTestHandler()
	client, server := feedH2(t, handler)

	feedBytes(t, handler, openssl.DataTypeWrite,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, client.block(t, h2RequestFields("GET", "/broken", "example.com")...)))
	feedBytes(t, handler, openssl.DataTypeRead,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, server.block(t, h2ResponseFields("200", "text/plain")...)))
	// Garbage HPACK on stream 3, then a healthy request on stream 5.
	feedBytes(t, handler, openssl.DataTypeWrite,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 3, []byte{0xff, 0xff, 0xff, 0xff}))
	after := newH2TestEncoder()
	feedBytes(t, handler, openssl.DataTypeWrite,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 5, after.block(t, h2RequestFields("GET", "/healthy", "example.com")...)))
	feedBytes(t, handler, openssl.DataTypeRead,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 5, server.block(t, h2ResponseFields("200", "text/plain")...)))

	document := closeAndParse(t, handler, sink)
	urls := make([]string, 0, len(document.Entries))
	for _, entry := range document.Entries {
		urls = append(urls, entry.Request.URL)
	}
	if len(document.Entries) != 2 {
		t.Fatalf("entries = %#v", urls)
	}
	if urls[0] != "https://example.com/broken" || urls[1] != "https://example.com/healthy" {
		t.Fatalf("urls = %#v", urls)
	}
}

func TestH2GoAwayFlushesOpenStreams(t *testing.T) {
	handler, sink := newTestHandler()
	client, _ := feedH2(t, handler)

	feedBytes(t, handler, openssl.DataTypeWrite,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders, 1, client.block(t, h2RequestFields("GET", "/goaway", "example.com")...)))
	feedBytes(t, handler, openssl.DataTypeRead, h2Frame(h2FrameGoAway, 0, 0, []byte{0, 0, 0, 0, 0, 0, 0, 0}))

	document := closeAndParse(t, handler, sink)
	if len(document.Entries) != 1 || document.Entries[0].Request.URL != "https://example.com/goaway" {
		t.Fatalf("entries = %#v", document.Entries)
	}
	if document.Entries[0].Response.Status != 0 {
		t.Fatalf("status = %d", document.Entries[0].Response.Status)
	}
}

func TestH2PrefaceSplitAcrossEvents(t *testing.T) {
	handler, sink := newTestHandler()
	client, server := newH2TestEncoder(), newH2TestEncoder()
	feedBytes(t, handler, openssl.DataTypeWrite, []byte(http2Preface[:9]))
	feedBytes(t, handler, openssl.DataTypeWrite, []byte(http2Preface[9:]))

	feedBytes(t, handler, openssl.DataTypeWrite,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, client.block(t, h2RequestFields("GET", "/preface", "example.com")...)))
	feedBytes(t, handler, openssl.DataTypeRead,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, server.block(t, h2ResponseFields("200", "text/plain")...)))

	document := closeAndParse(t, handler, sink)
	if len(document.Entries) != 1 || document.Entries[0].Request.URL != "https://example.com/preface" {
		t.Fatalf("entries = %#v", document.Entries)
	}
}

func TestH2BadPaddingKeepsPipeline(t *testing.T) {
	handler, sink := newTestHandler()
	client, server := feedH2(t, handler)

	for _, streamID := range []uint32{1, 3, 5} {
		feedBytes(t, handler, openssl.DataTypeWrite,
			h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, streamID,
				client.block(t, h2RequestFields("GET", fmt.Sprintf("/p%d", streamID), "example.com")...)))
	}
	feedBytes(t, handler, openssl.DataTypeRead,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, server.block(t, h2ResponseFields("200", "text/plain")...)))
	// Padding longer than the payload is a stream error on 3.
	feedBytes(t, handler, openssl.DataTypeRead, h2Frame(h2FrameData, h2FlagPadded|h2FlagEndStream, 3, []byte{9, 'a'}))
	feedBytes(t, handler, openssl.DataTypeRead,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 5, server.block(t, h2ResponseFields("200", "text/plain")...)))

	document := closeAndParse(t, handler, sink)
	urls := make([]string, 0, len(document.Entries))
	for _, entry := range document.Entries {
		urls = append(urls, entry.Request.URL)
	}
	if len(urls) != 3 {
		t.Fatalf("urls = %#v", urls)
	}
	if urls[0] != "https://example.com/p1" || urls[1] != "https://example.com/p3" || urls[2] != "https://example.com/p5" {
		t.Fatalf("urls = %#v", urls)
	}
}

func TestH2PushPromise(t *testing.T) {
	handler, sink := newTestHandler()
	client, server := feedH2(t, handler)

	feedBytes(t, handler, openssl.DataTypeWrite,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, client.block(t, h2RequestFields("GET", "/index", "example.com")...)))
	feedBytes(t, handler, openssl.DataTypeRead,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, server.block(t, h2ResponseFields("200", "text/html")...)))

	pushPayload := binary.BigEndian.AppendUint32(nil, 2)
	pushPayload = append(pushPayload, server.block(t, h2RequestFields("GET", "/pushed.css", "example.com")...)...)
	feedBytes(t, handler, openssl.DataTypeRead, h2Frame(h2FramePushPromise, h2FlagEndHeaders, 1, pushPayload))
	feedBytes(t, handler, openssl.DataTypeRead,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders, 2, server.block(t, h2ResponseFields("200", "text/css")...)))
	feedBytes(t, handler, openssl.DataTypeRead, h2Frame(h2FrameData, h2FlagEndStream, 2, []byte("body{}")))

	document := closeAndParse(t, handler, sink)
	if len(document.Entries) != 2 {
		t.Fatalf("entries = %#v\n%s", document.Entries, sink.String())
	}
	if document.Entries[1].Request.URL != "https://example.com/pushed.css" ||
		document.Entries[1].Response.Content.Text != "body{}" {
		t.Fatalf("pushed entry = %#v", document.Entries[1])
	}
}

func TestH2AfterH1OnReusedDescriptor(t *testing.T) {
	handler, sink := newTestHandler()
	feed(t, handler, 31, 7, openssl.DataTypeWrite, "GET /first HTTP/1.1\r\nHost: example.com\r\n\r\n")
	feed(t, handler, 31, 7, openssl.DataTypeRead, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

	client, server := feedH2(t, handler)
	feedBytes(t, handler, openssl.DataTypeWrite,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, client.block(t, h2RequestFields("GET", "/second", "example.com")...)))
	feedBytes(t, handler, openssl.DataTypeRead,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, server.block(t, h2ResponseFields("200", "text/plain")...)))

	document := closeAndParse(t, handler, sink)
	if len(document.Entries) != 2 {
		t.Fatalf("entries = %d, want 2\n%s", len(document.Entries), sink.String())
	}
	if document.Entries[0].Request.HTTPVersion != "HTTP/1.1" ||
		document.Entries[1].Request.HTTPVersion != http2Version {
		t.Fatalf("versions = %q/%q", document.Entries[0].Request.HTTPVersion, document.Entries[1].Request.HTTPVersion)
	}
	if document.Entries[1].Request.URL != "https://example.com/second" {
		t.Fatalf("url = %q", document.Entries[1].Request.URL)
	}
}

func TestH1AfterH2OnReusedDescriptor(t *testing.T) {
	handler, sink := newTestHandler()
	client, server := feedH2(t, handler)
	feedBytes(t, handler, openssl.DataTypeWrite,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, client.block(t, h2RequestFields("GET", "/first", "example.com")...)))
	feedBytes(t, handler, openssl.DataTypeRead,
		h2Frame(h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, 1, server.block(t, h2ResponseFields("200", "text/plain")...)))
	feedBytes(t, handler, openssl.DataTypeRead, h2Frame(h2FrameGoAway, 0, 0, make([]byte, 8)))

	feed(t, handler, 31, 7, openssl.DataTypeWrite, "GET /second HTTP/1.1\r\nHost: example.com\r\n\r\n")
	feed(t, handler, 31, 7, openssl.DataTypeRead, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

	document := closeAndParse(t, handler, sink)
	if len(document.Entries) != 2 {
		t.Fatalf("entries = %d, want 2\n%s", len(document.Entries), sink.String())
	}
	if document.Entries[0].Request.HTTPVersion != http2Version ||
		document.Entries[1].Request.HTTPVersion != "HTTP/1.1" {
		t.Fatalf("versions = %q/%q", document.Entries[0].Request.HTTPVersion, document.Entries[1].Request.HTTPVersion)
	}
	if document.Entries[1].Request.URL != "https://example.com/second" {
		t.Fatalf("url = %q", document.Entries[1].Request.URL)
	}
}

func TestH1AfterPrefaceStillParses(t *testing.T) {
	handler, sink := newTestHandler()
	feed(t, handler, 5, 9, openssl.DataTypeWrite, "GET /h1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	feed(t, handler, 5, 9, openssl.DataTypeRead, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")

	document := closeAndParse(t, handler, sink)
	if len(document.Entries) != 1 || document.Entries[0].Request.HTTPVersion != "HTTP/1.1" {
		t.Fatalf("entries = %#v", document.Entries)
	}
}
