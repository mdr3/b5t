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
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gojue/ecapture/v2/internal/output/har"
	"github.com/gojue/ecapture/v2/internal/output/writers"
	"github.com/gojue/ecapture/v2/internal/probe/openssl"
)

var fixedTime = time.Date(2026, time.November, 17, 13, 0, 0, 0, time.UTC)

type bufferSink struct {
	bytes.Buffer
}

func (b *bufferSink) Name() string { return "buffer" }
func (b *bufferSink) Flush() error { return nil }
func (b *bufferSink) Close() error { return nil }

type xmlDocument struct {
	XMLName     xml.Name  `xml:"items"`
	BurpVersion string    `xml:"burpVersion,attr"`
	ExportTime  string    `xml:"exportTime,attr"`
	Items       []xmlItem `xml:"item"`
}

type xmlItem struct {
	Time           string  `xml:"time"`
	URL            string  `xml:"url"`
	Host           xmlHost `xml:"host"`
	Port           int     `xml:"port"`
	Protocol       string  `xml:"protocol"`
	Method         string  `xml:"method"`
	Path           string  `xml:"path"`
	Extension      string  `xml:"extension"`
	Request        string  `xml:"request"`
	Status         int     `xml:"status"`
	ResponseLength int     `xml:"responselength"`
	MimeType       string  `xml:"mimetype"`
	Response       string  `xml:"response"`
	Comment        string  `xml:"comment"`
}

type xmlHost struct {
	IP   string `xml:"ip,attr"`
	Name string `xml:",chardata"`
}

func writeDocument(t *testing.T, entries ...har.Entry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := NewWriter(&buffer)
	writer.SetClock(func() time.Time { return fixedTime })
	for _, entry := range entries {
		if err := writer.WriteEntry(entry); err != nil {
			t.Fatalf("WriteEntry() error: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}
	return buffer.Bytes()
}

func parseDocument(t *testing.T, data []byte) xmlDocument {
	t.Helper()
	var document xmlDocument
	if err := xml.Unmarshal(data, &document); err != nil {
		t.Fatalf("document is not well-formed XML: %v\n%s", err, data)
	}
	return document
}

func decodePayload(t *testing.T, encoded string) string {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	return string(decoded)
}

func TestH1Transaction(t *testing.T) {
	entry := har.Entry{
		Request: har.Request{
			Method:      "GET",
			URL:         "https://example.com:8443/api/items.json?x=1&y=2",
			HTTPVersion: "HTTP/1.1",
			Headers: []har.NameValue{
				{Name: "Host", Value: "example.com"},
				{Name: "Accept", Value: "*/*"},
			},
		},
		Response: har.Response{
			Status:      200,
			HTTPVersion: "HTTP/1.1",
			Headers: []har.NameValue{
				{Name: "Content-Type", Value: "application/json"},
				{Name: "Content-Length", Value: "11"},
			},
			Content: har.Content{Size: 11, MimeType: "application/json", Text: `{"ok":true}`},
		},
		ServerIPAddress: "93.184.216.34",
	}

	data := writeDocument(t, entry)
	document := parseDocument(t, data)
	if document.BurpVersion != BurpVersion {
		t.Fatalf("burpVersion = %q", document.BurpVersion)
	}
	if document.ExportTime != "Tue Nov 17 13:00:00 UTC 2026" {
		t.Fatalf("exportTime = %q", document.ExportTime)
	}
	if len(document.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(document.Items))
	}
	item := document.Items[0]
	if item.Time != document.ExportTime {
		t.Fatalf("time = %q, exportTime = %q", item.Time, document.ExportTime)
	}
	if item.URL != entry.Request.URL || item.Method != "GET" || item.Path != "/api/items.json?x=1&y=2" {
		t.Fatalf("target = %#v", item)
	}
	if item.Host.IP != "93.184.216.34" || item.Host.Name != "example.com" {
		t.Fatalf("host = %#v", item.Host)
	}
	if item.Port != 8443 || item.Protocol != "https" {
		t.Fatalf("port/protocol = %d/%q", item.Port, item.Protocol)
	}
	if item.Extension != "json" || item.MimeType != "JSON" {
		t.Fatalf("extension/mimetype = %q/%q", item.Extension, item.MimeType)
	}
	if item.Status != 200 {
		t.Fatalf("status = %d", item.Status)
	}
	if item.Comment != "" {
		t.Fatalf("comment = %q", item.Comment)
	}

	wantRequest := "GET /api/items.json?x=1&y=2 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"
	if got := decodePayload(t, item.Request); got != wantRequest {
		t.Fatalf("request = %q, want %q", got, wantRequest)
	}
	wantResponse := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}"
	if got := decodePayload(t, item.Response); got != wantResponse {
		t.Fatalf("response = %q, want %q", got, wantResponse)
	}
	if item.ResponseLength != len(wantResponse) {
		t.Fatalf("responselength = %d, want %d", item.ResponseLength, len(wantResponse))
	}
}

func TestH2PseudoHeadersAreNormalized(t *testing.T) {
	entry := har.Entry{
		Request: har.Request{
			Method:      "POST",
			URL:         "https://example.com/v1/upload?q=1",
			HTTPVersion: "h2",
			Headers: []har.NameValue{
				{Name: ":method", Value: "POST"},
				{Name: ":authority", Value: "example.com:443"},
				{Name: ":scheme", Value: "https"},
				{Name: ":path", Value: "/v1/upload?q=1"},
				{Name: "content-type", Value: "application/json"},
				{Name: "x-custom", Value: "yes"},
			},
			PostData: &har.PostData{MimeType: "application/json", Text: `{}`},
		},
		Response: har.Response{
			Status:      0,
			HTTPVersion: "h2",
			Headers: []har.NameValue{
				{Name: ":status", Value: "201"},
				{Name: "content-type", Value: "application/json"},
			},
			Content: har.Content{Size: 2, MimeType: "application/json", Text: "{}"},
		},
	}

	document := parseDocument(t, writeDocument(t, entry))
	item := document.Items[0]
	if item.Status != 201 || item.Path != "/v1/upload?q=1" || item.Port != 443 {
		t.Fatalf("item = %#v", item)
	}
	if item.Host.Name != "example.com" {
		t.Fatalf("host = %#v", item.Host)
	}
	request := decodePayload(t, item.Request)
	lines := strings.Split(request, "\r\n")
	if len(lines) < 2 || !strings.HasPrefix(lines[0], "POST /v1/upload?q=1 HTTP/1.1") {
		t.Fatalf("request line = %q", lines)
	}
	if lines[1] != "Host: example.com:443" {
		t.Fatalf("injected host = %q", lines[1])
	}
	for _, line := range lines {
		if strings.HasPrefix(line, ":") {
			t.Fatalf("pseudo-header leaked into request: %q", line)
		}
	}
	response := decodePayload(t, item.Response)
	for _, line := range strings.Split(response, "\r\n") {
		if strings.HasPrefix(line, ":") {
			t.Fatalf("pseudo-header leaked into response: %q", line)
		}
	}
	if !strings.HasPrefix(response, "HTTP/1.1 201 Created\r\n") {
		t.Fatalf("response line = %q", response)
	}
}

func TestItemChildOrder(t *testing.T) {
	entry := har.Entry{Request: har.Request{Method: "GET", URL: "https://example.com/a", HTTPVersion: "HTTP/1.1"}}
	data := writeDocument(t, entry)

	decoder := xml.NewDecoder(bytes.NewReader(data))
	depth := 0
	itemDepth := -1
	var names []string
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		switch element := token.(type) {
		case xml.StartElement:
			depth++
			if element.Name.Local == "item" {
				itemDepth = depth
				continue
			}
			if itemDepth >= 0 && depth == itemDepth+1 {
				names = append(names, element.Name.Local)
			}
		case xml.EndElement:
			if element.Name.Local == "item" {
				itemDepth = -1
			}
			depth--
		}
	}
	want := []string{"time", "url", "host", "port", "protocol", "method", "path", "extension",
		"request", "status", "responselength", "mimetype", "response", "comment"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("child order = %v, want %v", names, want)
	}
}

func TestMappings(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		status    int
		mimeType  string
		extension string
		port      int
		protocol  string
		mimetype  string
	}{
		{name: "json", url: "https://h/api/a.JSON", status: 200, mimeType: "application/json", extension: "json", port: 443, protocol: "https", mimetype: "JSON"},
		{name: "html with parameters", url: "https://h/a.html", status: 200, mimeType: "text/html; charset=utf-8", extension: "html", port: 443, protocol: "https", mimetype: "HTML"},
		{name: "javascript", url: "https://h/a.js", status: 200, mimeType: "application/javascript", extension: "js", port: 443, protocol: "https", mimetype: "script"},
		{name: "text javascript", url: "https://h/a.mjs", status: 200, mimeType: "text/javascript", extension: "mjs", port: 443, protocol: "https", mimetype: "script"},
		{name: "css", url: "https://h/a.css", status: 200, mimeType: "text/css", extension: "css", port: 443, protocol: "https", mimetype: "CSS"},
		{name: "xml", url: "https://h/a.xml", status: 200, mimeType: "application/xml", extension: "xml", port: 443, protocol: "https", mimetype: "XML"},
		{name: "unknown type", url: "https://h/a.bin", status: 200, mimeType: "application/octet-stream", extension: "bin", port: 443, protocol: "https", mimetype: "Other"},
		{name: "no extension", url: "https://h/noext", status: 200, mimeType: "text/plain", extension: "null", port: 443, protocol: "https", mimetype: "Other"},
		{name: "dot in directory", url: "https://h/dir.v2/file", status: 200, mimeType: "", extension: "null", port: 443, protocol: "https", mimetype: "Other"},
		{name: "compound extension", url: "https://h/a.tar.gz", status: 200, mimeType: "", extension: "gz", port: 443, protocol: "https", mimetype: "Other"},
		{name: "http default port", url: "http://h/a", status: 200, mimeType: "", extension: "null", port: 80, protocol: "http", mimetype: "Other"},
		{name: "explicit port", url: "https://h:8443/a", status: 200, mimeType: "", extension: "null", port: 8443, protocol: "https", mimetype: "Other"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry := har.Entry{
				Request: har.Request{Method: "GET", URL: test.url, HTTPVersion: "HTTP/1.1"},
				Response: har.Response{
					Status:  test.status,
					Content: har.Content{MimeType: test.mimeType},
				},
			}
			item := parseDocument(t, writeDocument(t, entry)).Items[0]
			if item.Extension != test.extension {
				t.Errorf("extension = %q, want %q", item.Extension, test.extension)
			}
			if item.MimeType != test.mimetype {
				t.Errorf("mimetype = %q, want %q", item.MimeType, test.mimetype)
			}
			if item.Port != test.port {
				t.Errorf("port = %d, want %d", item.Port, test.port)
			}
			if item.Protocol != test.protocol {
				t.Errorf("protocol = %q, want %q", item.Protocol, test.protocol)
			}
		})
	}
}

func TestMissingServerIP(t *testing.T) {
	entry := har.Entry{Request: har.Request{Method: "GET", URL: "https://example.com/", HTTPVersion: "HTTP/1.1"}}
	data := writeDocument(t, entry)
	if !bytes.Contains(data, []byte(`<host ip="">example.com</host>`)) {
		t.Fatalf("host element = %s", data)
	}
	item := parseDocument(t, data).Items[0]
	if item.Host.IP != "" || item.Host.Name != "example.com" {
		t.Fatalf("host = %#v", item.Host)
	}
}

func TestEmptyStatusEmitsEmptyResponse(t *testing.T) {
	entry := har.Entry{
		Request: har.Request{Method: "GET", URL: "https://example.com/pending", HTTPVersion: "h2"},
		Response: har.Response{
			Status:  0,
			Content: har.Content{Text: "ignored", MimeType: "application/json"},
		},
	}
	item := parseDocument(t, writeDocument(t, entry)).Items[0]
	if item.Status != 0 || item.ResponseLength != 0 || item.MimeType != "Other" {
		t.Fatalf("item = %#v", item)
	}
	if got := decodePayload(t, item.Response); got != "" {
		t.Fatalf("response = %q, want empty", got)
	}
	if !strings.HasPrefix(decodePayload(t, item.Request), "GET /pending HTTP/1.1\r\nHost: example.com\r\n\r\n") {
		t.Fatalf("request = %q", decodePayload(t, item.Request))
	}
}

func TestCDATATerminatorInBody(t *testing.T) {
	body := "left]]>right"
	entry := har.Entry{
		Request: har.Request{Method: "POST", URL: "https://example.com/a.html", HTTPVersion: "HTTP/1.1"},
		Response: har.Response{
			Status:  200,
			Headers: []har.NameValue{{Name: "Content-Type", Value: "text/html"}},
			Content: har.Content{Size: int64(len(body)), MimeType: "text/html", Text: body},
		},
	}
	item := parseDocument(t, writeDocument(t, entry)).Items[0]
	want := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + body
	if got := decodePayload(t, item.Response); got != want {
		t.Fatalf("response = %q, want %q", got, want)
	}
}

func TestBase64BodyIsDecoded(t *testing.T) {
	body := []byte{0xff, 0xfe, 0x00, 0x01}
	entry := har.Entry{
		Request: har.Request{Method: "GET", URL: "https://example.com/bin", HTTPVersion: "HTTP/1.1"},
		Response: har.Response{
			Status:  200,
			Headers: []har.NameValue{{Name: "Content-Type", Value: "application/octet-stream"}},
			Content: har.Content{
				Size:     int64(len(body)),
				MimeType: "application/octet-stream",
				Text:     base64.StdEncoding.EncodeToString(body),
				Encoding: "base64",
			},
		},
	}
	item := parseDocument(t, writeDocument(t, entry)).Items[0]
	decoded, err := base64.StdEncoding.DecodeString(item.Response)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if !bytes.HasSuffix(decoded, body) {
		t.Fatalf("response = %x", decoded)
	}
}

func TestEmptyDocumentIsWellFormed(t *testing.T) {
	data := writeDocument(t)
	document := parseDocument(t, data)
	if len(document.Items) != 0 || document.BurpVersion != BurpVersion {
		t.Fatalf("document = %#v", document)
	}
	if document.ExportTime != "Tue Nov 17 13:00:00 UTC 2026" {
		t.Fatalf("exportTime = %q", document.ExportTime)
	}
}

func TestFileSinkProducesWellFormedDocument(t *testing.T) {
	path := t.TempDir() + "/capture.xml"
	sink, err := writers.NewWriterFactory().CreateEventSink(writers.EventSinkOptions{
		Address: path,
		Format:  writers.EventFormatBurpXML,
	})
	if err != nil {
		t.Fatalf("CreateEventSink() error: %v", err)
	}
	handler := NewHandler(sink)
	write := func(dataType int64, payload string) {
		t.Helper()
		event := &openssl.Event{DataType: dataType, Pid: 12, Fd: 4}
		copy(event.Data[:], payload)
		event.DataLen = int32(len(payload))
		if err := handler.Handle(event); err != nil {
			t.Fatalf("Handle() error: %v", err)
		}
	}
	write(openssl.DataTypeWrite, "GET /file HTTP/1.1\r\nHost: example.com\r\n\r\n")
	write(openssl.DataTypeRead, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	if err := handler.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	document := parseDocument(t, data)
	if len(document.Items) != 1 || document.Items[0].Path != "/file" {
		t.Fatalf("items = %#v", document.Items)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %o, want 600", info.Mode().Perm())
	}
}

func TestHandlerProducesImportableXML(t *testing.T) {
	var buffer bufferSink
	handler := NewHandler(&buffer)
	if handler.Name() != HandlerName || handler.Writer() == nil {
		t.Fatalf("handler identity = %q", handler.Name())
	}
	if handler.Supports(nil) || !handler.Supports(&openssl.Event{}) {
		t.Fatal("Supports() result is wrong")
	}

	write := func(dataType int64, payload string) {
		t.Helper()
		event := &openssl.Event{DataType: dataType, Pid: 4, Fd: 9}
		copy(event.Data[:], payload)
		event.DataLen = int32(len(payload))
		if err := handler.Handle(event); err != nil {
			t.Fatalf("Handle() error: %v", err)
		}
	}
	write(openssl.DataTypeWrite, "GET /from-handler HTTP/1.1\r\nHost: example.com\r\n\r\n")
	write(openssl.DataTypeRead, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	if err := handler.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}
	if err := handler.Close(); err != nil {
		t.Fatalf("second Close() error: %v", err)
	}

	item := parseDocument(t, buffer.Bytes()).Items[0]
	if item.Path != "/from-handler" || item.Status != 200 {
		t.Fatalf("item = %#v", item)
	}
}
