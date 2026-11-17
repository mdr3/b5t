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

// Package har reconstructs HTTP Archive (HAR 1.2) documents from decrypted
// TLS application data captured by the OpenSSL probe.
package har

// Version is the HAR specification version emitted by this package.
const Version = "1.2"

// Creator identifies the tool that produced the archive.
type Creator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Page groups entries that belong to one navigation. ecapture does not track
// navigations, so Pages is present but always empty.
type Page struct {
	StartedDateTime string      `json:"startedDateTime"`
	ID              string      `json:"id"`
	Title           string      `json:"title"`
	PageTimings     PageTimings `json:"pageTimings"`
}

// PageTimings carries the page load milestones.
type PageTimings struct {
	OnContentLoad float64 `json:"onContentLoad"`
	OnLoad        float64 `json:"onLoad"`
}

// Log is the top-level HAR document.
type Log struct {
	Version string  `json:"version"`
	Creator Creator `json:"creator"`
	Pages   []Page  `json:"pages"`
	Entries []Entry `json:"entries"`
}

// HAR is the archive root that wraps exactly one Log.
type HAR struct {
	Log Log `json:"log"`
}

// NameValue is a header or query-string item.
type NameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Cookie is a request or response cookie.
type Cookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Expires  string `json:"expires,omitempty"`
	HTTPOnly bool   `json:"httpOnly,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
}

// PostData is the request body.
type PostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
	Comment  string `json:"comment,omitempty"`
}

// Request describes one HTTP request.
type Request struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Cookies     []Cookie    `json:"cookies"`
	Headers     []NameValue `json:"headers"`
	QueryString []NameValue `json:"queryString"`
	PostData    *PostData   `json:"postData,omitempty"`
	HeadersSize int64       `json:"headersSize"`
	BodySize    int64       `json:"bodySize"`
}

// Content describes a response body.
type Content struct {
	Size     int64  `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
	Encoding string `json:"encoding,omitempty"`
	Comment  string `json:"comment,omitempty"`
}

// Response describes one HTTP response.
type Response struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Cookies     []Cookie    `json:"cookies"`
	Headers     []NameValue `json:"headers"`
	Content     Content     `json:"content"`
	RedirectURL string      `json:"redirectURL"`
	HeadersSize int64       `json:"headersSize"`
	BodySize    int64       `json:"bodySize"`
}

// Cache records cache usage. ecapture cannot see the browser cache, so both
// members stay absent.
type Cache struct {
	BeforeRequest *CacheEntry `json:"beforeRequest,omitempty"`
	AfterRequest  *CacheEntry `json:"afterRequest,omitempty"`
}

// CacheEntry is one cache state snapshot.
type CacheEntry struct {
	Expires    string `json:"expires,omitempty"`
	LastAccess string `json:"lastAccess,omitempty"`
	ETag       string `json:"eTag,omitempty"`
	HitCount   int    `json:"hitCount"`
}

// Timings holds the request/response phase durations in milliseconds. A value
// of -1 means "not applicable"; ecapture measures each phase it observes.
type Timings struct {
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}

// Entry is one complete request/response pair.
type Entry struct {
	StartedDateTime string   `json:"startedDateTime"`
	Time            float64  `json:"time"`
	Request         Request  `json:"request"`
	Response        Response `json:"response"`
	Cache           Cache    `json:"cache"`
	Timings         Timings  `json:"timings"`
	ServerIPAddress string   `json:"serverIPAddress,omitempty"`
	Connection      string   `json:"connection,omitempty"`
	// StreamID is an HTTP/2 extension field (underscore-prefixed per HAR 1.2).
	StreamID uint32 `json:"_streamId,omitempty"`
}
