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

// Package burpxml renders captured HTTP exchanges as a Burp Suite bulk-export
// XML document. Burp, ZAP and Caido import the format, which carries each
// request/response pair as base64 inside CDATA.
package burpxml

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gojue/ecapture/v2/internal/output/har"
)

const (
	// BurpVersion is the Burp release whose export schema is emitted.
	BurpVersion = "2026.1"
	// timeLayout is the timestamp format used by exportTime and <time>.
	timeLayout = "Mon Jan _2 15:04:05 UTC 2006"
	// xmlHeader opens every document.
	xmlHeader = "<?xml version=\"1.0\"?>\n"
)

// Writer streams one Burp bulk-export document to an io.Writer. The root
// element is written lazily before the first item and closed by Flush or
// Close. WriteEntry, Flush and Close are safe for concurrent use.
type Writer struct {
	mu            sync.Mutex
	writer        io.Writer
	now           func() time.Time
	headerWritten bool
	finished      bool
	itemCount     int
	writeErr      error
}

// NewWriter creates a writer that timestamps the document with the wall clock.
func NewWriter(writer io.Writer) *Writer {
	return &Writer{writer: writer, now: time.Now}
}

// SetClock replaces the timestamp source. It must be called before the first
// entry for the document header to reflect it.
func (w *Writer) SetClock(now func() time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if now == nil {
		now = time.Now
	}
	w.now = now
}

// Items returns the number of transactions written so far.
func (w *Writer) Items() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.itemCount
}

// WriteEntry appends one transaction to the document.
func (w *Writer) WriteEntry(entry har.Entry) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.finished {
		return errors.New("burp XML writer is closed")
	}
	if w.writer == nil {
		return errors.New("burp XML writer is nil")
	}
	if w.writeErr != nil {
		return w.writeErr
	}

	now := w.now()
	item, err := buildItem(entry, now)
	if err != nil {
		return fmt.Errorf("build burp XML item: %w", err)
	}

	var payload []byte
	if !w.headerWritten {
		payload = append(payload, w.headerLocked(now)...)
	}
	payload = append(payload, item...)
	if _, err = w.writer.Write(payload); err != nil {
		w.writeErr = err
		return err
	}
	w.itemCount++
	return nil
}

func (w *Writer) headerLocked(now time.Time) []byte {
	w.headerWritten = true
	return []byte(fmt.Sprintf("%s<items burpVersion=%q exportTime=%q>\n",
		xmlHeader, BurpVersion, now.UTC().Format(timeLayout)))
}

// Flush terminates the document and flushes the destination when it supports
// flushing.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.finishLocked(); err != nil {
		return err
	}
	if flusher, ok := w.writer.(interface{ Flush() error }); ok {
		return flusher.Flush()
	}
	return nil
}

// Close terminates the document and closes the destination when it is a
// closer. Close is idempotent.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.finished && w.writeErr != nil {
		return w.writeErr
	}
	finishErr := w.finishLocked()
	var closeErr error
	if closer, ok := w.writer.(io.Closer); ok {
		closeErr = closer.Close()
	}
	return errors.Join(finishErr, closeErr)
}

func (w *Writer) finishLocked() error {
	if w.finished {
		return w.writeErr
	}
	w.finished = true
	if w.writer == nil {
		return nil
	}
	var payload []byte
	if !w.headerWritten {
		payload = append(payload, w.headerLocked(w.now())...)
	}
	payload = append(payload, "</items>\n"...)
	if _, err := w.writer.Write(payload); err != nil {
		w.writeErr = err
		return err
	}
	return w.writeErr
}

// buildItem renders one <item>. Every transport detail is normalized to an
// HTTP/1.1 message so Burp and compatible importers can replay it.
func buildItem(entry har.Entry, now time.Time) ([]byte, error) {
	h2 := entry.Request.HTTPVersion == "h2" || entry.Response.HTTPVersion == "h2"

	parsed, err := url.Parse(entry.Request.URL)
	if err != nil {
		parsed = &url.URL{}
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" {
		scheme = "https"
	}
	authority := headerValue(entry.Request.Headers, ":authority")
	host := parsed.Hostname()
	if host == "" {
		host = authorityHost(authority)
	}
	port := 443
	if scheme == "http" {
		port = 80
	}
	if explicit := parsed.Port(); explicit != "" {
		if number, convErr := strconv.Atoi(explicit); convErr == nil {
			port = number
		}
	} else if explicit := authorityPort(authority); explicit != "" {
		if number, convErr := strconv.Atoi(explicit); convErr == nil {
			port = number
		}
	}

	requestPath := parsed.RequestURI()
	if requestPath == "" {
		requestPath = "/"
	}
	if h2 {
		if pseudo := headerValue(entry.Request.Headers, ":path"); pseudo != "" {
			requestPath = pseudo
		}
	}

	extension := extensionOf(requestPath)

	status := entry.Response.Status
	if h2 {
		if pseudo := headerValue(entry.Response.Headers, ":status"); pseudo != "" {
			if number, convErr := strconv.Atoi(pseudo); convErr == nil {
				status = number
			}
		}
	}

	requestBody := requestBodyBytes(entry)
	requestText := rawRequest(entry, requestPath, authority, host, port, scheme, h2, requestBody)

	responseText := []byte(nil)
	mimeType := "Other"
	if status != 0 {
		responseText = rawResponse(entry, status, h2)
		mimeType = mimeTypeOf(entry.Response.Content.MimeType)
	}

	var buf bytes.Buffer
	buf.WriteString("  <item>\n")
	buf.WriteString("    <time>")
	buf.WriteString(now.UTC().Format(timeLayout))
	buf.WriteString("</time>\n")
	buf.WriteString("    <url>")
	writeCDATA(&buf, entry.Request.URL)
	buf.WriteString("</url>\n")
	buf.WriteString("    <host ip=\"")
	escapeText(&buf, entry.ServerIPAddress)
	buf.WriteString("\">")
	escapeText(&buf, host)
	buf.WriteString("</host>\n")
	buf.WriteString("    <port>")
	buf.WriteString(strconv.Itoa(port))
	buf.WriteString("</port>\n")
	buf.WriteString("    <protocol>")
	buf.WriteString(scheme)
	buf.WriteString("</protocol>\n")
	buf.WriteString("    <method>")
	writeCDATA(&buf, entry.Request.Method)
	buf.WriteString("</method>\n")
	buf.WriteString("    <path>")
	writeCDATA(&buf, requestPath)
	buf.WriteString("</path>\n")
	buf.WriteString("    <extension>")
	buf.WriteString(extension)
	buf.WriteString("</extension>\n")
	buf.WriteString("    <request base64=\"true\">")
	writeCDATA(&buf, base64.StdEncoding.EncodeToString(requestText))
	buf.WriteString("</request>\n")
	buf.WriteString("    <status>")
	buf.WriteString(strconv.Itoa(status))
	buf.WriteString("</status>\n")
	buf.WriteString("    <responselength>")
	buf.WriteString(strconv.Itoa(len(responseText)))
	buf.WriteString("</responselength>\n")
	buf.WriteString("    <mimetype>")
	buf.WriteString(mimeType)
	buf.WriteString("</mimetype>\n")
	buf.WriteString("    <response base64=\"true\">")
	writeCDATA(&buf, base64.StdEncoding.EncodeToString(responseText))
	buf.WriteString("</response>\n")
	buf.WriteString("    <comment></comment>\n")
	buf.WriteString("  </item>\n")
	return buf.Bytes(), nil
}

// rawRequest builds the wire-form HTTP/1.1 request. HTTP/2 pseudo-headers are
// dropped and the authority becomes a Host header.
func rawRequest(entry har.Entry, requestPath, authority, host string, port int, scheme string, h2 bool, body []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString(entry.Request.Method)
	buf.WriteByte(' ')
	buf.WriteString(requestPath)
	buf.WriteString(" HTTP/1.1\r\n")
	if h2 {
		hostValue := authority
		if hostValue == "" {
			hostValue = host
			if (scheme == "https" && port != 443) || (scheme == "http" && port != 80) {
				hostValue = net.JoinHostPort(host, strconv.Itoa(port))
			}
		}
		buf.WriteString("Host: ")
		buf.WriteString(hostValue)
		buf.WriteString("\r\n")
	}
	for _, header := range entry.Request.Headers {
		if h2 && strings.HasPrefix(header.Name, ":") {
			continue
		}
		buf.WriteString(header.Name)
		buf.WriteString(": ")
		buf.WriteString(header.Value)
		buf.WriteString("\r\n")
	}
	buf.WriteString("\r\n")
	buf.Write(body)
	return buf.Bytes()
}

// rawResponse builds the wire-form HTTP/1.1 response. A missing response
// (status 0) yields no payload at all.
func rawResponse(entry har.Entry, status int, h2 bool) []byte {
	var buf bytes.Buffer
	buf.WriteString("HTTP/1.1 ")
	buf.WriteString(strconv.Itoa(status))
	buf.WriteByte(' ')
	buf.WriteString(http.StatusText(status))
	buf.WriteString("\r\n")
	for _, header := range entry.Response.Headers {
		if h2 && strings.HasPrefix(header.Name, ":") {
			continue
		}
		buf.WriteString(header.Name)
		buf.WriteString(": ")
		buf.WriteString(header.Value)
		buf.WriteString("\r\n")
	}
	buf.WriteString("\r\n")
	buf.Write(bodyBytes(entry.Response.Content))
	return buf.Bytes()
}

// requestBodyBytes returns the HAR request body, decoding the base64 marker
// used for binary octet-stream payloads.
func requestBodyBytes(entry har.Entry) []byte {
	if entry.Request.PostData == nil {
		return nil
	}
	text := entry.Request.PostData.Text
	if strings.EqualFold(entry.Request.PostData.MimeType, "application/octet-stream") {
		if decoded, err := base64.StdEncoding.DecodeString(text); err == nil {
			return decoded
		}
	}
	return []byte(text)
}

// bodyBytes returns decoded body bytes for a HAR content block.
func bodyBytes(content har.Content) []byte {
	if content.Text == "" {
		return nil
	}
	if content.Encoding == "base64" {
		if decoded, err := base64.StdEncoding.DecodeString(content.Text); err == nil {
			return decoded
		}
	}
	return []byte(content.Text)
}

func headerValue(headers []har.NameValue, name string) string {
	for _, header := range headers {
		if strings.EqualFold(header.Name, name) {
			return header.Value
		}
	}
	return ""
}

func authorityHost(authority string) string {
	if authority == "" {
		return ""
	}
	if host, _, err := splitAuthority(authority); err == nil {
		return host
	}
	return authority
}

func authorityPort(authority string) string {
	if authority == "" {
		return ""
	}
	if _, port, err := splitAuthority(authority); err == nil {
		return port
	}
	return ""
}

func splitAuthority(authority string) (host, port string, err error) {
	parsed, err := url.Parse("//" + authority)
	if err != nil {
		return "", "", err
	}
	return parsed.Hostname(), parsed.Port(), nil
}

// extensionOf returns the lowercased extension without its dot, or the
// literal "null" when the path has none.
func extensionOf(requestPath string) string {
	target, _, _ := strings.Cut(requestPath, "?")
	extension := strings.TrimPrefix(path.Ext(target), ".")
	if extension == "" {
		return "null"
	}
	return strings.ToLower(extension)
}

// mimeTypeOf maps a content type to the fixed Burp mimetype vocabulary.
func mimeTypeOf(contentType string) string {
	value := strings.ToLower(contentType)
	if semicolon := strings.IndexByte(value, ';'); semicolon >= 0 {
		value = value[:semicolon]
	}
	value = strings.TrimSpace(value)
	switch {
	case value == "":
		return "Other"
	case strings.Contains(value, "json"):
		return "JSON"
	case strings.Contains(value, "html"):
		return "HTML"
	case strings.Contains(value, "javascript"), strings.Contains(value, "ecmascript"):
		return "script"
	case strings.Contains(value, "css"):
		return "CSS"
	case strings.Contains(value, "xml"):
		return "XML"
	default:
		return "Other"
	}
}

// writeCDATA writes a CDATA section, splitting any embedded terminator.
func writeCDATA(buf *bytes.Buffer, value string) {
	buf.WriteString("<![CDATA[")
	buf.WriteString(strings.ReplaceAll(value, "]]>", "]]]]><![CDATA[>"))
	buf.WriteString("]]>")
}

// escapeText escapes character data and attribute values.
func escapeText(buf *bytes.Buffer, value string) {
	_ = xml.EscapeText(buf, []byte(value))
}
