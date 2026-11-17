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
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gojue/ecapture/v2/internal/probe/openssl"
)

const (
	// maxStreamBuffer bounds the unparsed bytes retained for one stream.
	maxStreamBuffer = 4 << 20
	// maxHeaderBytes bounds a single start line plus header block.
	maxHeaderBytes = 64 << 10
	// maxBodyText bounds the body text stored in one HAR entry.
	maxBodyText = 1 << 20
	// maxStreams bounds the number of concurrently correlated connections.
	maxStreams = 4096
	// maxPendingRequests bounds pipelined requests awaiting responses.
	maxPendingRequests = 1024
)

var crlf = []byte("\r\n")
var headerTerminator = []byte("\r\n\r\n")

type parseStatus uint8

const (
	parseComplete parseStatus = iota
	parseNeedMore
	parseGarbage
)

type streamKey struct {
	pid   uint32
	fd    uint32
	sock  uint64
	tuple string
}

type parsedRequest struct {
	method        string
	target        string
	version       string
	host          string
	headers       []NameValue
	body          []byte
	bodySize      int64
	bodyTruncated bool
	headerSize    int64
	streamID      uint32
	start         time.Time
	end           time.Time
}

type parsedResponse struct {
	status        int
	statusText    string
	version       string
	headers       []NameValue
	body          []byte
	bodySize      int64
	bodyTruncated bool
	headerSize    int64
	start         time.Time
	end           time.Time
}

type stream struct {
	key       streamKey
	tuple     string
	mode      streamMode
	reqBuf    []byte
	respBuf   []byte
	pending   []*parsedRequest
	h2req     h2Dir
	h2resp    h2Dir
	h2        map[uint32]*h2Stream
	h2Stopped bool
	reqStart  time.Time
	respStart time.Time
	lastUsed  time.Time
}

// Correlator pairs request and response byte streams per connection and emits
// complete HAR entries to the recorder. Feed is safe for concurrent use.
type Correlator struct {
	mu       sync.Mutex
	recorder *Recorder
	streams  map[streamKey]*stream
}

// NewCorrelator creates a correlator that appends completed entries to rec.
func NewCorrelator(rec *Recorder) *Correlator {
	return &Correlator{recorder: rec, streams: make(map[streamKey]*stream)}
}

// Feed consumes one TLS data event. Parse failures never escape: incomplete
// messages simply stay buffered until more bytes arrive.
func (c *Correlator) Feed(event *openssl.Event) {
	if event == nil || c.recorder == nil {
		return
	}
	data := event.GetData()
	if len(data) == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := eventTime(event)
	key := keyForEvent(event)
	st := c.streams[key]
	if st == nil {
		st = &stream{key: key}
		c.streams[key] = st
		c.evictLocked()
	}
	st.lastUsed = now
	if event.Tuple != "" {
		st.tuple = event.Tuple
	}

	if event.DataType == openssl.DataTypeWrite {
		if st.mode == streamModeHTTP2 {
			st.h2req.buf = append(st.h2req.buf, data...)
		} else {
			if len(st.reqBuf) == 0 {
				st.reqStart = now
			}
			st.reqBuf = append(st.reqBuf, data...)
			c.detectMode(st)
			if st.mode == streamModeHTTP2 {
				st.h2req.buf = append(st.h2req.buf, st.reqBuf...)
				st.reqBuf = nil
				if len(st.respBuf) > 0 {
					st.h2resp.buf = append(st.h2resp.buf, st.respBuf...)
					st.respBuf = nil
				}
			}
		}
	} else {
		if st.mode == streamModeHTTP2 {
			st.h2resp.buf = append(st.h2resp.buf, data...)
		} else {
			if len(st.respBuf) == 0 {
				st.respStart = now
			}
			st.respBuf = append(st.respBuf, data...)
		}
	}

	switch st.mode {
	case streamModeHTTP2:
		c.h2Consume(st, now)
	case streamModeHTTP1:
		if event.DataType == openssl.DataTypeWrite {
			c.consumeRequests(st, now)
		} else {
			c.consumeResponses(st, now)
		}
	}

	if len(st.reqBuf) == 0 && len(st.respBuf) == 0 && len(st.pending) == 0 &&
		len(st.h2req.buf) == 0 && len(st.h2resp.buf) == 0 && len(st.h2) == 0 {
		// Keep the stream for keep-alive reuse; it is cheap and bounded.
		return
	}
	if len(st.reqBuf) > maxStreamBuffer || len(st.respBuf) > maxStreamBuffer ||
		len(st.h2req.buf) > maxStreamBuffer || len(st.h2resp.buf) > maxStreamBuffer {
		// A stream that cannot be framed is hopeless; start it over.
		if st.mode == streamModeHTTP2 {
			c.h2Flush(st, now)
			st.h2Stopped = true
		}
		st.reqBuf = st.reqBuf[:0]
		st.respBuf = st.respBuf[:0]
		st.pending = st.pending[:0]
	}
}

func keyForEvent(event *openssl.Event) streamKey {
	switch {
	case event.Pid != 0:
		return streamKey{pid: event.Pid, fd: event.Fd}
	case event.Sock != 0:
		return streamKey{sock: event.Sock}
	case event.Tuple != "":
		return streamKey{tuple: event.Tuple}
	default:
		return streamKey{}
	}
}

func (c *Correlator) evictLocked() {
	if len(c.streams) <= maxStreams {
		return
	}
	var oldestKey streamKey
	var oldest time.Time
	first := true
	for key, st := range c.streams {
		if first || st.lastUsed.Before(oldest) {
			oldestKey = key
			oldest = st.lastUsed
			first = false
		}
	}
	delete(c.streams, oldestKey)
}

func (c *Correlator) consumeRequests(st *stream, now time.Time) {
	if c.h2TryUpgrade(st) {
		c.h2Consume(st, now)
		return
	}
	for len(st.reqBuf) > 0 {
		start := scanRequestStart(st.reqBuf)
		if start < 0 {
			if len(st.reqBuf) > maxHeaderBytes && bytes.IndexByte(st.reqBuf, '\n') < 0 {
				st.reqBuf = st.reqBuf[:0]
			}
			return
		}
		st.reqBuf = st.reqBuf[start:]

		req, consumed, status := parseRequest(st.reqBuf, st.reqStart, now)
		switch status {
		case parseNeedMore:
			return
		case parseGarbage:
			st.reqBuf = st.reqBuf[1:]
			continue
		}
		st.reqBuf = st.reqBuf[consumed:]
		if len(st.pending) >= maxPendingRequests {
			st.pending = st.pending[1:]
		}
		st.pending = append(st.pending, req)
		if len(st.reqBuf) > 0 {
			// A pipelined request may follow in the same segment.
			st.reqStart = now
		}
	}
	c.consumeResponses(st, now)
}

func (c *Correlator) consumeResponses(st *stream, now time.Time) {
	for len(st.pending) > 0 && len(st.respBuf) > 0 {
		start := scanResponseStart(st.respBuf)
		if start < 0 {
			return
		}
		st.respBuf = st.respBuf[start:]

		resp, consumed, status := parseResponse(st.respBuf, st.pending[0].method, st.respStart, now)
		switch status {
		case parseNeedMore:
			return
		case parseGarbage:
			st.respBuf = st.respBuf[1:]
			continue
		}
		st.respBuf = st.respBuf[consumed:]
		req := st.pending[0]
		st.pending = st.pending[1:]
		c.emit(st, req, resp)
		if len(st.respBuf) > 0 {
			st.respStart = now
		}
	}
}

func (c *Correlator) emit(st *stream, req *parsedRequest, resp *parsedResponse) {
	entry := buildEntry(st, req, resp)
	c.recorder.WriteEntry(entry)
}

func buildEntry(st *stream, req *parsedRequest, resp *parsedResponse) Entry {
	requestBody := encodeBody(req.body, req.bodyTruncated)
	responseBody := encodeBody(resp.body, resp.bodyTruncated)

	send := durationMillis(req.end.Sub(req.start))
	wait := durationMillis(resp.start.Sub(req.end))
	receive := durationMillis(resp.end.Sub(resp.start))

	h2 := req.version == http2Version
	reqHeadersSize := req.headerSize
	respHeadersSize := resp.headerSize
	statusText := resp.statusText
	if h2 {
		// HPACK-compressed header blocks have no on-the-wire octet count that
		// matches HAR semantics, so both sides report -1 (HAR 1.2 §5.2).
		reqHeadersSize = -1
		respHeadersSize = -1
		statusText = ""
	}

	entry := Entry{
		StartedDateTime: formatTimestamp(req.start),
		Time:            send + wait + receive,
		Request: Request{
			Method:      req.method,
			URL:         absoluteURL(st.tuple, req),
			HTTPVersion: req.version,
			Cookies:     parseRequestCookies(req.headers),
			Headers:     nonNilHeaders(req.headers),
			QueryString: queryString(req.target),
			HeadersSize: reqHeadersSize,
			BodySize:    req.bodySize,
		},
		Response: Response{
			Status:      resp.status,
			StatusText:  statusText,
			HTTPVersion: resp.version,
			Cookies:     parseResponseCookies(resp.headers),
			Headers:     nonNilHeaders(resp.headers),
			Content: Content{
				Size:     resp.bodySize,
				MimeType: contentType(resp.headers, responseBody.encoding),
				Text:     responseBody.text,
				Encoding: responseBody.encoding,
				Comment:  responseBody.comment,
			},
			RedirectURL: headerValue(resp.headers, "location"),
			HeadersSize: respHeadersSize,
			BodySize:    resp.bodySize,
		},
		Cache:    Cache{},
		Timings:  Timings{Send: send, Wait: wait, Receive: receive},
		StreamID: req.streamID,
	}
	if host := hostFromTuple(st.tuple); host != "" {
		entry.ServerIPAddress = hostOnly(host)
		entry.Connection = host
	}
	if req.bodySize > 0 || len(req.body) > 0 {
		entry.Request.PostData = &PostData{
			MimeType: contentType(req.headers, requestBody.encoding),
			Text:     requestBody.text,
			Comment:  requestBody.comment,
		}
	}
	return entry
}

type encodedBody struct {
	text     string
	encoding string
	comment  string
}

func encodeBody(body []byte, truncated bool) encodedBody {
	if len(body) == 0 {
		return encodedBody{}
	}
	result := encodedBody{}
	if truncated {
		result.comment = fmt.Sprintf("body truncated to %d bytes", maxBodyText)
	}
	if utf8.Valid(body) {
		result.text = string(body)
		return result
	}
	result.text = base64.StdEncoding.EncodeToString(body)
	result.encoding = "base64"
	return result
}

func durationMillis(d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(d) / float64(time.Millisecond)
}

func formatTimestamp(t time.Time) string {
	return t.Format("2006-01-02T15:04:05.000-07:00")
}

func absoluteURL(tuple string, req *parsedRequest) string {
	target := req.target
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return target
	}
	host := req.host
	if host == "" {
		host = hostFromTuple(tuple)
	}
	if host == "" {
		host = "unknown"
	}
	switch {
	case target == "*":
		return "https://" + host + "/*"
	case strings.HasPrefix(target, "/"):
		return "https://" + host + target
	default:
		return "https://" + host + "/" + target
	}
}

func hostFromTuple(tuple string) string {
	if tuple == "" {
		return ""
	}
	parts := strings.Split(tuple, "-")
	host := strings.TrimSpace(parts[len(parts)-1])
	if host == "" {
		return ""
	}
	return host
}

func hostOnly(hostPort string) string {
	if strings.HasPrefix(hostPort, "[") {
		if end := strings.Index(hostPort, "]"); end >= 0 {
			return hostPort[1:end]
		}
	}
	if colon := strings.LastIndex(hostPort, ":"); colon > 0 {
		return hostPort[:colon]
	}
	return hostPort
}

func queryString(target string) []NameValue {
	parsed, err := url.Parse(target)
	if err != nil {
		return []NameValue{}
	}
	values := parsed.Query()
	items := make([]NameValue, 0, len(values))
	for name, entries := range values {
		for _, value := range entries {
			items = append(items, NameValue{Name: name, Value: value})
		}
	}
	sortNameValues(items)
	return items
}

func sortNameValues(items []NameValue) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j].Name < items[j-1].Name; j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}

func parseRequestCookies(headers []NameValue) []Cookie {
	cookies := make([]Cookie, 0)
	for _, header := range headers {
		if !strings.EqualFold(header.Name, "cookie") {
			continue
		}
		for _, pair := range strings.Split(header.Value, ";") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			name, value, found := strings.Cut(pair, "=")
			if !found {
				continue
			}
			cookies = append(cookies, Cookie{Name: name, Value: value})
		}
	}
	return cookies
}

func parseResponseCookies(headers []NameValue) []Cookie {
	cookies := make([]Cookie, 0)
	for _, header := range headers {
		if !strings.EqualFold(header.Name, "set-cookie") {
			continue
		}
		first, rest, _ := strings.Cut(header.Value, ";")
		name, value, found := strings.Cut(strings.TrimSpace(first), "=")
		if !found {
			continue
		}
		cookie := Cookie{Name: name, Value: value}
		for _, attribute := range strings.Split(rest, ";") {
			attribute = strings.TrimSpace(attribute)
			switch {
			case strings.EqualFold(attribute, "secure"):
				cookie.Secure = true
			case strings.EqualFold(attribute, "httponly"):
				cookie.HTTPOnly = true
			case strings.HasPrefix(strings.ToLower(attribute), "path="):
				cookie.Path = attribute[len("path="):]
			case strings.HasPrefix(strings.ToLower(attribute), "domain="):
				cookie.Domain = attribute[len("domain="):]
			}
		}
		cookies = append(cookies, cookie)
	}
	return cookies
}

func contentType(headers []NameValue, encoding string) string {
	if value := headerValue(headers, "content-type"); value != "" {
		return value
	}
	if encoding == "base64" {
		return "application/octet-stream"
	}
	return "text/plain"
}

func headerValue(headers []NameValue, name string) string {
	for _, header := range headers {
		if strings.EqualFold(header.Name, name) {
			return header.Value
		}
	}
	return ""
}

func nonNilHeaders(headers []NameValue) []NameValue {
	if headers == nil {
		return []NameValue{}
	}
	return headers
}

func scanRequestStart(buf []byte) int {
	for offset := 0; offset < len(buf); offset++ {
		if b := buf[offset]; b < 'A' || b > 'Z' {
			continue
		}
		newline := bytes.IndexByte(buf[offset:], '\n')
		if newline < 0 {
			if looksLikeRequestPrefix(buf[offset:]) {
				return offset
			}
			continue
		}
		line := bytes.TrimSuffix(buf[offset:offset+newline], crlf)
		if _, _, _, ok := parseRequestLine(line); ok {
			return offset
		}
	}
	return -1
}

func scanResponseStart(buf []byte) int {
	for offset := 0; offset < len(buf); offset++ {
		rest := buf[offset:]
		if !looksLikeResponsePrefix(rest) {
			continue
		}
		newline := bytes.IndexByte(rest, '\n')
		if newline < 0 {
			return offset
		}
		line := bytes.TrimSuffix(rest[:newline], crlf)
		if _, _, _, ok := parseStatusLine(line); ok {
			return offset
		}
	}
	return -1
}

func looksLikeRequestPrefix(buf []byte) bool {
	if len(buf) == 0 || len(buf) > maxHeaderBytes {
		return false
	}
	space := bytes.IndexByte(buf, ' ')
	if space < 0 {
		return len(buf) <= 16 && validMethodBytes(buf)
	}
	return validMethodBytes(buf[:space])
}

func looksLikeResponsePrefix(buf []byte) bool {
	if len(buf) > len("HTTP/1.") {
		buf = buf[:len("HTTP/1.")]
	}
	return bytes.HasPrefix([]byte("HTTP/1."), buf)
}

func validMethodBytes(method []byte) bool {
	if len(method) == 0 || len(method) > 16 {
		return false
	}
	for _, b := range method {
		if (b < 'A' || b > 'Z') && b != '-' {
			return false
		}
	}
	return true
}

func parseRequestLine(line []byte) (method, target, version string, ok bool) {
	parts := bytes.SplitN(line, []byte(" "), 3)
	if len(parts) != 3 || !validMethodBytes(parts[0]) || len(parts[1]) == 0 {
		return "", "", "", false
	}
	httpVersion := string(parts[2])
	if !strings.HasPrefix(httpVersion, "HTTP/1.") {
		return "", "", "", false
	}
	return string(parts[0]), string(parts[1]), httpVersion, true
}

func parseStatusLine(line []byte) (version string, status int, statusText string, ok bool) {
	parts := bytes.SplitN(line, []byte(" "), 3)
	if len(parts) < 2 || len(parts[1]) != 3 {
		return "", 0, "", false
	}
	httpVersion := string(parts[0])
	if !strings.HasPrefix(httpVersion, "HTTP/1.") {
		return "", 0, "", false
	}
	code, err := strconv.Atoi(string(parts[1]))
	if err != nil || code < 100 || code > 999 {
		return "", 0, "", false
	}
	if len(parts) == 3 {
		statusText = string(parts[2])
	}
	return httpVersion, code, statusText, true
}

func parseRequest(buf []byte, start, end time.Time) (*parsedRequest, int, parseStatus) {
	lineEnd := bytes.Index(buf, crlf)
	if lineEnd < 0 {
		if len(buf) > maxHeaderBytes {
			return nil, 0, parseGarbage
		}
		return nil, 0, parseNeedMore
	}
	method, target, version, ok := parseRequestLine(buf[:lineEnd])
	if !ok {
		return nil, 0, parseGarbage
	}
	headerEnd := bytes.Index(buf[lineEnd:], headerTerminator)
	if headerEnd < 0 {
		if len(buf) > maxHeaderBytes {
			return nil, 0, parseGarbage
		}
		return nil, 0, parseNeedMore
	}
	headerEnd += lineEnd
	bodyOffset := headerEnd + len(headerTerminator)
	if bodyOffset > maxHeaderBytes {
		return nil, 0, parseGarbage
	}
	headerBlockStart := lineEnd + len(crlf)
	if headerBlockStart > headerEnd {
		headerBlockStart = headerEnd
	}

	headers := parseHeaders(buf[headerBlockStart:headerEnd])
	chunked := headerHasToken(headers, "transfer-encoding", "chunked")
	bodyLen := int64(0)
	if !chunked {
		if raw := headerValue(headers, "content-length"); raw != "" {
			parsed, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
			if err != nil || parsed < 0 {
				return nil, 0, parseGarbage
			}
			bodyLen = parsed
		}
	}

	req := &parsedRequest{
		method:     method,
		target:     target,
		version:    version,
		host:       strings.TrimSpace(headerValue(headers, "host")),
		headers:    headers,
		headerSize: int64(bodyOffset),
		start:      start,
	}
	if chunked {
		body, total, consumed, status := parseChunked(buf[bodyOffset:])
		if status != parseComplete {
			if status == parseGarbage {
				return nil, 0, parseGarbage
			}
			return nil, 0, parseNeedMore
		}
		req.body = body
		req.bodySize = int64(total)
		req.bodyTruncated = int64(len(body)) < int64(total)
		req.end = end
		return req, bodyOffset + consumed, parseComplete
	}
	if bodyLen > 0 {
		if int64(len(buf)-bodyOffset) < bodyLen {
			if len(buf) > maxStreamBuffer {
				return nil, 0, parseGarbage
			}
			return nil, 0, parseNeedMore
		}
		req.bodySize = bodyLen
		appendBody(&req.body, buf[bodyOffset:bodyOffset+int(bodyLen)], &req.bodyTruncated)
		consumed := bodyOffset + int(bodyLen)
		req.end = end
		return req, consumed, parseComplete
	}
	req.end = end
	return req, bodyOffset, parseComplete
}

func parseResponse(buf []byte, method string, start, end time.Time) (*parsedResponse, int, parseStatus) {
	lineEnd := bytes.Index(buf, crlf)
	if lineEnd < 0 {
		if len(buf) > maxHeaderBytes {
			return nil, 0, parseGarbage
		}
		return nil, 0, parseNeedMore
	}
	version, status, statusText, ok := parseStatusLine(buf[:lineEnd])
	if !ok {
		return nil, 0, parseGarbage
	}
	headerEnd := bytes.Index(buf[lineEnd:], headerTerminator)
	if headerEnd < 0 {
		if len(buf) > maxHeaderBytes {
			return nil, 0, parseGarbage
		}
		return nil, 0, parseNeedMore
	}
	headerEnd += lineEnd
	bodyOffset := headerEnd + len(headerTerminator)
	if bodyOffset > maxHeaderBytes {
		return nil, 0, parseGarbage
	}
	headerBlockStart := lineEnd + len(crlf)
	if headerBlockStart > headerEnd {
		headerBlockStart = headerEnd
	}

	headers := parseHeaders(buf[headerBlockStart:headerEnd])
	resp := &parsedResponse{
		status:     status,
		statusText: statusText,
		version:    version,
		headers:    headers,
		headerSize: int64(bodyOffset),
		start:      start,
	}

	if status < 200 || status == 204 || status == 304 || strings.EqualFold(method, "HEAD") {
		resp.end = end
		return resp, bodyOffset, parseComplete
	}
	if headerHasToken(headers, "transfer-encoding", "chunked") {
		body, total, consumed, parseState := parseChunked(buf[bodyOffset:])
		if parseState != parseComplete {
			if parseState == parseGarbage {
				return nil, 0, parseGarbage
			}
			return nil, 0, parseNeedMore
		}
		resp.body = body
		resp.bodySize = int64(total)
		resp.bodyTruncated = int64(len(body)) < int64(total)
		resp.end = end
		return resp, bodyOffset + consumed, parseComplete
	}
	if raw := headerValue(headers, "content-length"); raw != "" {
		bodyLen, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil || bodyLen < 0 {
			return nil, 0, parseGarbage
		}
		if int64(len(buf)-bodyOffset) < bodyLen {
			if len(buf) > maxStreamBuffer {
				return nil, 0, parseGarbage
			}
			return nil, 0, parseNeedMore
		}
		resp.bodySize = bodyLen
		appendBody(&resp.body, buf[bodyOffset:bodyOffset+int(bodyLen)], &resp.bodyTruncated)
		resp.end = end
		return resp, bodyOffset + int(bodyLen), parseComplete
	}
	resp.end = end
	return resp, bodyOffset, parseComplete
}

func parseHeaders(block []byte) []NameValue {
	headers := make([]NameValue, 0, 8)
	for _, line := range bytes.Split(block, crlf) {
		if len(line) == 0 {
			continue
		}
		name, value, found := bytes.Cut(line, []byte(":"))
		if !found {
			continue
		}
		headers = append(headers, NameValue{
			Name:  string(bytes.TrimSpace(name)),
			Value: string(bytes.TrimSpace(value)),
		})
	}
	return headers
}

func headerHasToken(headers []NameValue, name, token string) bool {
	for _, header := range headers {
		if !strings.EqualFold(header.Name, name) {
			continue
		}
		for _, part := range strings.Split(header.Value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func parseChunked(buf []byte) (body []byte, total int, consumed int, status parseStatus) {
	position := 0
	for {
		newline := bytes.Index(buf[position:], crlf)
		if newline < 0 {
			return nil, 0, 0, parseNeedMore
		}
		line := buf[position : position+newline]
		if semi := bytes.IndexByte(line, ';'); semi >= 0 {
			line = line[:semi]
		}
		size, err := strconv.ParseInt(strings.TrimSpace(string(line)), 16, 64)
		if err != nil || size < 0 {
			return nil, 0, 0, parseGarbage
		}
		position += newline + len(crlf)
		if size == 0 {
			for {
				trailerEnd := bytes.Index(buf[position:], crlf)
				if trailerEnd < 0 {
					return nil, 0, 0, parseNeedMore
				}
				position += trailerEnd + len(crlf)
				if trailerEnd == 0 {
					return body, total, position, parseComplete
				}
			}
		}
		if size > int64(len(buf)-position) {
			return nil, 0, 0, parseNeedMore
		}
		total += int(size)
		truncated := false
		appendBody(&body, buf[position:position+int(size)], &truncated)
		position += int(size)
		if !bytes.HasPrefix(buf[position:], crlf) {
			return nil, 0, 0, parseGarbage
		}
		position += len(crlf)
	}
}

func appendBody(dst *[]byte, src []byte, truncated *bool) {
	remaining := maxBodyText - len(*dst)
	if remaining <= 0 {
		*truncated = true
		return
	}
	if len(src) > remaining {
		*truncated = true
		src = src[:remaining]
	}
	*dst = append(*dst, src...)
}

var (
	clockOffsetOnce sync.Once
	clockOffset     int64
	clockOffsetErr  error
)

// eventTime converts the monotonic eBPF timestamp to wall-clock time. When the
// timestamp is missing or the clock offset cannot be read, time.Now is used.
func eventTime(event *openssl.Event) time.Time {
	if event.Timestamp == 0 {
		return time.Now()
	}
	clockOffsetOnce.Do(func() {
		clockOffset, clockOffsetErr = openssl.GetClockOffset()
	})
	if clockOffsetErr != nil {
		return time.Now()
	}
	return time.Unix(0, int64(event.Timestamp)+clockOffset)
}
