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
	"encoding/binary"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2/hpack"
)

// http2Version is the HAR httpVersion reported for HTTP/2 exchanges. The
// protocol stays visible in the archive even though entries are rendered like
// HTTP/1 messages, the same way an intercepting proxy presents them.
const http2Version = "HTTP/2"

// http2Preface is the client connection preface that selects h2 framing for a
// stream.
const http2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

var http2PrefaceBytes = []byte(http2Preface)

const (
	// h2FrameHeaderLen is the fixed frame header size from RFC 9113.
	h2FrameHeaderLen = 9
	// h2MaxFrameSize bounds a single frame payload we are willing to buffer.
	h2MaxFrameSize = maxStreamBuffer
	// h2MaxHeaderBlock bounds one reassembled header block.
	h2MaxHeaderBlock = maxHeaderBytes
	// h2DefaultTableSize is the HPACK initial dynamic table size.
	h2DefaultTableSize = 4096
	// h2AllowedTableSize is the largest dynamic table size a peer may select.
	h2AllowedTableSize = 64 << 10
	// h2MaxStreams bounds the concurrently tracked h2 streams of a connection.
	h2MaxStreams = 1024
)

// HTTP/2 frame types used by the decoder.
const (
	h2FrameData         = 0x0
	h2FrameHeaders      = 0x1
	h2FramePriority     = 0x2
	h2FrameRSTStream    = 0x3
	h2FrameSettings     = 0x4
	h2FramePushPromise  = 0x5
	h2FramePing         = 0x6
	h2FrameGoAway       = 0x7
	h2FrameWindowUpdate = 0x8
	h2FrameContinuation = 0x9
)

// HTTP/2 frame flags used by the decoder.
const (
	h2FlagEndStream  = 0x1
	h2FlagEndHeaders = 0x4
	h2FlagPadded     = 0x8
	h2FlagPriority   = 0x20
)

var errH2Truncated = errors.New("h2: truncated frame payload")

type streamMode uint8

const (
	streamModeUnknown streamMode = iota
	streamModeHTTP1
	streamModeHTTP2
)

// h2Dir is the per-connection-direction framing state. HPACK blocks are
// contiguous within a direction, so one pending header block is enough.
type h2Dir struct {
	buf         []byte
	dec         *hpack.Decoder
	sawSettings bool

	inBlock   bool
	blockID   uint32
	blockBuf  []byte
	endStream bool
	pushed    bool
}

// h2Stream is one multiplexed HTTP/2 stream (distinct from the correlated
// TLS connection, also called a stream in this package).
type h2Stream struct {
	id         uint32
	req        *parsedRequest
	resp       *parsedResponse
	reqWire    int64
	respWire   int64
	reqClosed  bool
	respClosed bool
	emitted    bool
	start      time.Time
}

func newH2Decoder() *hpack.Decoder {
	decoder := hpack.NewDecoder(h2DefaultTableSize, nil)
	decoder.SetAllowedMaxDynamicTableSize(h2AllowedTableSize)
	decoder.SetMaxStringLength(h2MaxHeaderBlock)
	return decoder
}

// detectMode inspects the first buffered client bytes and selects h2 when the
// connection preface shows up. Anything else keeps the h1 path. No bytes are
// consumed unless the preface is found.
func (c *Correlator) detectMode(st *stream) {
	if st.mode != streamModeUnknown || len(st.reqBuf) == 0 {
		return
	}
	window := st.reqBuf
	if len(window) > 64 {
		window = window[:64]
	}
	if idx := bytes.Index(window, http2PrefaceBytes); idx >= 0 {
		st.reqBuf = st.reqBuf[idx+len(http2PrefaceBytes):]
		st.mode = streamModeHTTP2
		st.h2req.dec = newH2Decoder()
		st.h2resp.dec = newH2Decoder()
		return
	}
	if bytes.HasPrefix(http2PrefaceBytes, st.reqBuf) {
		// A partial preface: wait for the rest.
		return
	}
	// A request line tells us this is h1 long before the preface could
	// complete, so ordinary traffic is not delayed.
	if bytes.Contains(window, []byte(" HTTP/1.")) || len(st.reqBuf) >= len(http2PrefaceBytes) {
		st.mode = streamModeHTTP1
	}
}

// h2TryUpgrade switches an h1 stream to h2 when a recycled descriptor starts a
// new connection with the client preface. Only idle h1 streams qualify, so a
// buffered request body can never be mistaken for a preface.
func (c *Correlator) h2TryUpgrade(st *stream) bool {
	if len(st.pending) != 0 || len(st.reqBuf) == 0 {
		return false
	}
	window := st.reqBuf
	if len(window) > 64 {
		window = window[:64]
	}
	idx := bytes.Index(window, http2PrefaceBytes)
	if idx < 0 {
		return false
	}
	rest := st.reqBuf[idx+len(http2PrefaceBytes):]
	responseBytes := st.respBuf
	st.h2req = h2Dir{dec: newH2Decoder()}
	st.h2resp = h2Dir{dec: newH2Decoder()}
	st.h2req.buf = append(st.h2req.buf, rest...)
	st.reqBuf = nil
	st.respBuf = nil
	if len(responseBytes) > 0 {
		st.h2resp.buf = append(st.h2resp.buf, responseBytes...)
	}
	st.mode = streamModeHTTP2
	st.h2Stopped = false
	return true
}

// h2TryDowngrade returns a stalled h2 stream to h1 when the framing looks like
// a new HTTP/1 connection on a recycled descriptor. Open h2 streams keep the
// connection in h2 mode.
func (c *Correlator) h2TryDowngrade(st *stream, now time.Time) bool {
	if len(st.h2) != 0 {
		return false
	}
	requestBytes := st.h2req.buf
	responseBytes := st.h2resp.buf
	st.h2req = h2Dir{}
	st.h2resp = h2Dir{}
	st.h2 = nil
	st.reqBuf = append(st.reqBuf, requestBytes...)
	if len(responseBytes) > 0 {
		st.respBuf = append(st.respBuf, responseBytes...)
	}
	st.mode = streamModeHTTP1
	st.h2Stopped = false
	c.consumeRequests(st, now)
	return true
}

// h2Consume drains framed bytes from both directions.
func (c *Correlator) h2Consume(st *stream, now time.Time) {
	if st.h2Stopped {
		// A recycled descriptor may carry a fresh HTTP/1 connection.
		if h2LooksLikeHTTP1(st.h2req.buf) {
			c.h2TryDowngrade(st, now)
		}
		return
	}
	c.h2ConsumeFrames(st, &st.h2req, true, now)
	c.h2ConsumeFrames(st, &st.h2resp, false, now)
}

// h2LooksLikeHTTP1 reports whether the buffered frame header has a length no
// h2 frame could carry, which is how an HTTP/1 request line (for example
// "GET /...") reads when parsed as a frame header.
func h2LooksLikeHTTP1(buf []byte) bool {
	if len(buf) < h2FrameHeaderLen {
		return false
	}
	length := int(buf[0])<<16 | int(buf[1])<<8 | int(buf[2])
	return length > h2MaxFrameSize
}

func (c *Correlator) h2ConsumeFrames(st *stream, dir *h2Dir, fromClient bool, now time.Time) {
	for st.mode == streamModeHTTP2 && !st.h2Stopped {
		if len(dir.buf) < h2FrameHeaderLen {
			return
		}
		length := int(dir.buf[0])<<16 | int(dir.buf[1])<<8 | int(dir.buf[2])
		frameType := dir.buf[3]
		flags := dir.buf[4]
		streamID := binary.BigEndian.Uint32(dir.buf[5:9]) & 0x7fffffff
		if length > h2MaxFrameSize {
			// The frame cannot be buffered at all. A recycled descriptor
			// serving HTTP/1 reads exactly like this; otherwise the
			// connection is unusable.
			if c.h2TryDowngrade(st, now) {
				return
			}
			c.h2Flush(st, now)
			st.h2Stopped = true
			return
		}
		total := h2FrameHeaderLen + length
		if len(dir.buf) < total {
			return
		}
		payload := dir.buf[h2FrameHeaderLen:total]
		dir.buf = dir.buf[total:]

		switch frameType {
		case h2FrameData:
			c.h2Data(st, streamID, flags, payload, fromClient, now)
		case h2FrameHeaders:
			c.h2Headers(st, dir, streamID, flags, payload, fromClient, now)
		case h2FrameContinuation:
			c.h2Continuation(st, dir, streamID, flags, payload, fromClient, now)
		case h2FramePriority, h2FramePing, h2FrameWindowUpdate:
			// Flow control and priority do not affect the reconstruction.
		case h2FrameSettings:
			if !fromClient {
				dir.sawSettings = true
			}
		case h2FrameRSTStream:
			if len(payload) < 4 {
				c.h2StreamError(st, streamID, now)
				continue
			}
			c.h2Close(st, streamID, now)
		case h2FramePushPromise:
			c.h2PushPromise(st, dir, flags, payload, now)
		case h2FrameGoAway:
			c.h2Flush(st, now)
			st.h2Stopped = true
			return
		default:
			// Unknown frame types must be ignored.
		}
		if st.mode != streamModeHTTP2 {
			return
		}
	}
}

func (c *Correlator) h2Data(st *stream, streamID uint32, flags byte, payload []byte, fromClient bool, now time.Time) {
	body, err := h2StripPadding(payload, flags)
	if err != nil {
		c.h2StreamError(st, streamID, now)
		return
	}
	s := st.h2[streamID]
	if s == nil {
		// Capture may start mid-connection; keep the body anyway.
		s = c.h2Stream(st, streamID, now)
		if fromClient {
			s.req = &parsedRequest{version: http2Version, start: now}
			s.reqWire = 0
		} else {
			s.reqClosed = true
		}
	}
	if fromClient {
		if s.req == nil {
			s.req = &parsedRequest{version: http2Version, start: now}
		}
		s.req.bodySize += int64(len(body))
		appendBody(&s.req.body, body, &s.req.bodyTruncated)
	} else {
		if s.resp == nil {
			s.resp = &parsedResponse{version: http2Version, start: now}
		}
		s.resp.bodySize += int64(len(body))
		appendBody(&s.resp.body, body, &s.resp.bodyTruncated)
	}
	if flags&h2FlagEndStream != 0 {
		c.h2EndSide(st, s, fromClient, now)
	}
}

func (c *Correlator) h2Headers(st *stream, dir *h2Dir, streamID uint32, flags byte, payload []byte, fromClient bool, now time.Time) {
	if dir.inBlock {
		// Another header block started before CONTINUATION finished.
		c.h2ConnectionError(st, now)
		return
	}
	fragment, err := h2StripPadding(payload, flags)
	if err != nil {
		c.h2StreamError(st, streamID, now)
		return
	}
	if flags&h2FlagPriority != 0 {
		if len(fragment) < 5 {
			c.h2StreamError(st, streamID, now)
			return
		}
		fragment = fragment[5:]
	}
	if streamID == 0 {
		c.h2ConnectionError(st, now)
		return
	}
	if fromClient {
		if st.h2req.dec == nil {
			st.h2req.dec = newH2Decoder()
		}
	} else if st.h2resp.dec == nil {
		st.h2resp.dec = newH2Decoder()
	}
	c.h2Stream(st, streamID, now)
	dir.startBlock(streamID, flags&h2FlagEndStream != 0, false)
	dir.blockBuf = append(dir.blockBuf, fragment...)
	if len(dir.blockBuf) > h2MaxHeaderBlock {
		c.h2HeaderBlockError(st, dir, streamID, fromClient, now)
		return
	}
	if flags&h2FlagEndHeaders != 0 {
		c.h2FinishBlock(st, dir, streamID, fromClient, now)
	}
}

func (c *Correlator) h2Continuation(st *stream, dir *h2Dir, streamID uint32, flags byte, payload []byte, fromClient bool, now time.Time) {
	if !dir.inBlock || dir.blockID != streamID {
		c.h2ConnectionError(st, now)
		return
	}
	if flags&h2FlagEndStream != 0 {
		// END_STREAM belongs on HEADERS, but some peers repeat it.
		dir.endStream = true
	}
	dir.blockBuf = append(dir.blockBuf, payload...)
	if len(dir.blockBuf) > h2MaxHeaderBlock {
		c.h2HeaderBlockError(st, dir, streamID, fromClient, now)
		return
	}
	if flags&h2FlagEndHeaders != 0 {
		c.h2FinishBlock(st, dir, streamID, fromClient, now)
	}
}

func (c *Correlator) h2PushPromise(st *stream, dir *h2Dir, flags byte, payload []byte, now time.Time) {
	if dir.inBlock {
		c.h2ConnectionError(st, now)
		return
	}
	body, err := h2StripPadding(payload, flags)
	if err != nil || len(body) < 4 {
		c.h2ConnectionError(st, now)
		return
	}
	promised := binary.BigEndian.Uint32(body[:4]) & 0x7fffffff
	body = body[4:]
	if flags&h2FlagPriority != 0 {
		if len(body) < 5 {
			c.h2ConnectionError(st, now)
			return
		}
		body = body[5:]
	}
	if promised == 0 {
		c.h2ConnectionError(st, now)
		return
	}
	if st.h2resp.dec == nil {
		st.h2resp.dec = newH2Decoder()
	}
	c.h2Stream(st, promised, now)
	dir.startBlock(promised, false, true)
	dir.blockBuf = append(dir.blockBuf, body...)
	if flags&h2FlagEndHeaders != 0 {
		c.h2FinishBlock(st, dir, promised, false, now)
	}
}

// h2HeaderBlockError abandons a header block that grew past the cap.
func (c *Correlator) h2HeaderBlockError(st *stream, dir *h2Dir, streamID uint32, fromClient bool, now time.Time) {
	dir.resetBlock()
	if fromClient {
		st.h2req.dec = newH2Decoder()
	} else {
		st.h2resp.dec = newH2Decoder()
	}
	c.h2StreamError(st, streamID, now)
}

// h2FinishBlock HPACK-decodes the reassembled block and turns it into request
// or response fields.
func (c *Correlator) h2FinishBlock(st *stream, dir *h2Dir, streamID uint32, fromClient bool, now time.Time) {
	block := dir.blockBuf
	endStream := dir.endStream
	pushed := dir.pushed
	dir.resetBlock()

	decoder := st.h2req.dec
	if !fromClient {
		decoder = st.h2resp.dec
	}
	if decoder == nil {
		decoder = newH2Decoder()
		if fromClient {
			st.h2req.dec = decoder
		} else {
			st.h2resp.dec = decoder
		}
	}
	fields, err := decoder.DecodeFull(block)
	if err != nil {
		// The dynamic table may be out of sync; restart it for this
		// direction and lose only this stream.
		if fromClient {
			st.h2req.dec = newH2Decoder()
		} else {
			st.h2resp.dec = newH2Decoder()
		}
		c.h2StreamError(st, streamID, now)
		return
	}
	headers := make([]NameValue, 0, len(fields))
	for _, field := range fields {
		headers = append(headers, NameValue{Name: field.Name, Value: field.Value})
	}

	s := st.h2[streamID]
	if s == nil {
		s = c.h2Stream(st, streamID, now)
	}
	if pushed {
		s.req = buildH2Request(headers, now, st.tuple)
		s.reqWire += int64(len(block) + h2FrameHeaderLen)
		s.reqClosed = true
	} else if fromClient {
		s.reqWire += int64(len(block) + h2FrameHeaderLen)
		if s.req == nil {
			s.req = buildH2Request(headers, now, st.tuple)
		} else if s.req.method == "" {
			applyH2Request(s.req, headers, st.tuple)
		} else {
			// Trailers after the body.
			s.req.headers = append(s.req.headers, headers...)
		}
	} else {
		s.respWire += int64(len(block) + h2FrameHeaderLen)
		if s.resp == nil {
			s.resp = buildH2Response(headers, now)
		} else {
			// Interim (1xx) responses may precede the final one.
			if s.resp.status == 0 || (s.resp.status >= 100 && s.resp.status < 200) {
				applyH2Status(s.resp, headers)
			}
			s.resp.headers = append(s.resp.headers, headers...)
		}
		if s.req == nil {
			// Response without a captured request.
			s.reqClosed = true
		}
	}
	if endStream {
		c.h2EndSide(st, s, fromClient, now)
	}
}

func (c *Correlator) h2EndSide(st *stream, s *h2Stream, fromClient bool, now time.Time) {
	if fromClient {
		if s.req != nil && s.req.end.IsZero() {
			s.req.end = now
			s.req.headerSize = s.reqWire
		}
		s.reqClosed = true
	} else {
		if s.resp != nil && s.resp.end.IsZero() {
			s.resp.end = now
			s.resp.headerSize = s.respWire
		}
		s.respClosed = true
	}
	if s.reqClosed && s.respClosed {
		c.h2EmitStream(st, s, now)
		delete(st.h2, s.id)
	}
}

// h2Close emits the partial entry (when a request was seen) and forgets the
// stream, as RST_STREAM or an unrecoverable stream error requires.
func (c *Correlator) h2Close(st *stream, streamID uint32, now time.Time) {
	s := st.h2[streamID]
	if s == nil {
		return
	}
	if s.req != nil || s.resp != nil {
		c.h2EmitStream(st, s, now)
	}
	delete(st.h2, streamID)
}

func (c *Correlator) h2StreamError(st *stream, streamID uint32, now time.Time) {
	c.h2Close(st, streamID, now)
}

// h2ConnectionError drops the framing state of the connection but keeps any
// collected entries.
func (c *Correlator) h2ConnectionError(st *stream, now time.Time) {
	c.h2Flush(st, now)
	st.h2Stopped = true
}

// h2Flush emits every still-open stream and clears the framing state.
func (c *Correlator) h2Flush(st *stream, now time.Time) {
	for _, s := range st.h2 {
		c.h2EmitStream(st, s, now)
	}
	st.h2 = make(map[uint32]*h2Stream)
	st.h2req = h2Dir{}
	st.h2resp = h2Dir{}
}

func (c *Correlator) h2EmitStream(st *stream, s *h2Stream, now time.Time) {
	if s.emitted {
		return
	}
	s.emitted = true
	req := s.req
	if req == nil {
		req = &parsedRequest{version: http2Version, target: "/", start: s.start}
	}
	if req.end.IsZero() {
		req.end = now
	}
	if req.headerSize == 0 {
		req.headerSize = s.reqWire
	}
	resp := s.resp
	if resp == nil {
		resp = &parsedResponse{version: http2Version, start: now}
	}
	if resp.start.IsZero() {
		resp.start = now
	}
	if resp.end.IsZero() {
		resp.end = resp.start
	}
	if resp.headerSize == 0 {
		resp.headerSize = s.respWire
	}
	c.emit(st, req, resp)
}

// h2Stream returns the stream state for id, creating it when needed. The
// oldest stream is flushed when the per-connection cap is reached.
func (c *Correlator) h2Stream(st *stream, id uint32, now time.Time) *h2Stream {
	if st.h2 == nil {
		st.h2 = make(map[uint32]*h2Stream)
	}
	if s := st.h2[id]; s != nil {
		return s
	}
	if len(st.h2) >= h2MaxStreams {
		var oldest *h2Stream
		for _, candidate := range st.h2 {
			if oldest == nil || candidate.start.Before(oldest.start) {
				oldest = candidate
			}
		}
		if oldest != nil {
			c.h2EmitStream(st, oldest, now)
			delete(st.h2, oldest.id)
		}
	}
	s := &h2Stream{id: id, start: now}
	st.h2[id] = s
	return s
}

func (d *h2Dir) startBlock(id uint32, endStream, pushed bool) {
	d.inBlock = true
	d.blockID = id
	d.blockBuf = d.blockBuf[:0]
	d.endStream = endStream
	d.pushed = pushed
}

func (d *h2Dir) resetBlock() {
	d.inBlock = false
	d.blockID = 0
	d.blockBuf = nil
	d.endStream = false
	d.pushed = false
}

func h2StripPadding(payload []byte, flags byte) ([]byte, error) {
	if flags&h2FlagPadded == 0 {
		return payload, nil
	}
	if len(payload) == 0 {
		return nil, errH2Truncated
	}
	padding := int(payload[0])
	if padding >= len(payload) {
		return nil, errH2Truncated
	}
	return payload[1 : len(payload)-padding], nil
}

func buildH2Request(fields []NameValue, now time.Time, tuple string) *parsedRequest {
	req := &parsedRequest{
		version: http2Version,
		start:   now,
	}
	applyH2Request(req, fields, tuple)
	return req
}

func applyH2Request(req *parsedRequest, fields []NameValue, tuple string) {
	req.headers = fields
	var scheme, authority, path string
	for _, field := range fields {
		switch field.Name {
		case ":method":
			req.method = field.Value
		case ":path":
			path = field.Value
		case ":authority":
			authority = field.Value
		case ":scheme":
			scheme = field.Value
		case "host":
			if authority == "" {
				authority = field.Value
			}
		}
	}
	if !strings.EqualFold(scheme, "http") {
		scheme = "https"
	}
	if authority == "" {
		authority = hostFromTuple(tuple)
	}
	if authority == "" {
		authority = "unknown"
	}
	req.host = authority
	if path == "" {
		path = "/"
	}
	switch {
	case strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://"):
		req.target = path
	case path == "*":
		req.target = scheme + "://" + authority + "/*"
	case strings.HasPrefix(path, "/"):
		req.target = scheme + "://" + authority + path
	default:
		req.target = scheme + "://" + authority + "/" + path
	}
}

func buildH2Response(fields []NameValue, now time.Time) *parsedResponse {
	resp := &parsedResponse{
		version: http2Version,
		headers: fields,
		start:   now,
	}
	applyH2Status(resp, fields)
	return resp
}

func applyH2Status(resp *parsedResponse, fields []NameValue) {
	for _, field := range fields {
		if field.Name != ":status" {
			continue
		}
		if code, err := strconv.Atoi(field.Value); err == nil && code >= 100 && code <= 999 {
			resp.status = code
			resp.statusText = http.StatusText(code)
		}
	}
}
