package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// tlsTainted tracks connections (keyed by client:port-server:port) where the
// client sent a TLS handshake to the plain HTTP port. Both the synthesized
// request and the server's 400 response are dropped for tainted connections.
var (
	tlsTaintedMu sync.Mutex
	tlsTainted   = make(map[string]bool)
)

func tlsTaintKey(clientNet, clientPort, serverNet, serverPort string) string {
	return clientNet + ":" + clientPort + "-" + serverNet + ":" + serverPort
}

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct {
	capturePort int
}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	seq            int // sequence number to distinguish multiple request/response pairs on the same connection
	capturePort    int
	junkLogged     bool // already synthesized an entry for the current run of non-HTTP bytes
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:         net,
		transport:   transport,
		r:           tcpreader.NewReaderStream(),
		capturePort: h.capturePort,
	}
	go hstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)
	for {
		// Peek at first bytes to determine if this is a request, response, or junk.
		// Using Peek (not ReadLine) so we don't consume data — then we pass buf
		// directly to ReadRequest/ReadResponse, avoiding nested bufio.Readers
		// which silently lose read-ahead data between messages.
		peeked, err := buf.Peek(8)
		if err == io.EOF {
			return
		}
		if err != nil {
			// Not enough data to peek 8 bytes but not EOF — try to skip past junk
			buf.ReadByte()
			continue
		}

		peekStr := string(peeked)

		if h.isHTTPRequest(peekStr) {
			req, err := http.ReadRequest(buf)
			if err != nil {
				log.Println("Error reading request", h.net, h.transport, ":", err)
				buf.ReadByte()
				continue
			}

			bodyBytes, err := io.ReadAll(req.Body)
			if err != nil {
				log.Println("Error reading request body", h.net, h.transport, ":", err)
				bodyBytes = []byte{}
			}
			req.Body.Close()

			h.seq++
			h.junkLogged = false
			h.logRequest(req, bodyBytes)
		} else if h.isHTTPResponse(peekStr) {
			resp, bodyBytes, err := parseResponseSafely(buf)
			if err != nil {
				log.Println("Error reading response", h.net, h.transport, ":", err)
				buf.ReadByte()
				continue
			}

			h.seq++
			h.junkLogged = false

			// The request stream might not have peeked the TLS bytes yet — give it
			// a brief grace period before we decide to log this response.
			if !h.isResponseToTaintedConnection() {
				time.Sleep(150 * time.Millisecond)
			}
			if h.isResponseToTaintedConnection() {
				continue
			}

			h.logResponse(resp, bodyBytes)
		} else {
			// Non-HTTP bytes on the client→server stream.
			isTLS := len(peeked) >= 3 && peeked[0] == 0x16 && peeked[1] == 0x03
			if isTLS && h.isClientToServer() {
				// Drop the whole connection silently — taint it so the server's
				// 400 response gets dropped on the other stream too. Defer the
				// clear well past any reasonable response-logging window so the
				// response stream's grace-period check still sees this tainted.
				h.markTLSTainted()
				io.Copy(io.Discard, buf)
				go func() {
					time.Sleep(5 * time.Second)
					h.clearTLSTaint()
				}()
				return
			}
			if !h.junkLogged && h.isClientToServer() {
				h.junkLogged = true
				h.seq++
				h.logUnparseable(peeked)
			}
			buf.ReadByte()
		}
	}
}

func (h *httpStream) isHTTPRequest(line string) bool {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"}
	for _, method := range methods {
		if strings.HasPrefix(line, method+" ") {
			return true
		}
	}
	return false
}

func (h *httpStream) isHTTPResponse(line string) bool {
	return strings.HasPrefix(line, "HTTP/")
}

// isClientToServer reports whether this stream's traffic is flowing toward the
// monitored capture port (i.e. inbound to our server).
func (h *httpStream) isClientToServer() bool {
	return h.transport.Dst().String() == strconv.Itoa(h.capturePort)
}

// markTLSTainted is called from the client→server stream when TLS bytes are
// detected. It records the connection 4-tuple so the response stream can
// recognize and drop the matching 400.
func (h *httpStream) markTLSTainted() {
	key := tlsTaintKey(h.net.Src().String(), h.transport.Src().String(), h.net.Dst().String(), h.transport.Dst().String())
	tlsTaintedMu.Lock()
	tlsTainted[key] = true
	tlsTaintedMu.Unlock()
}

func (h *httpStream) clearTLSTaint() {
	key := tlsTaintKey(h.net.Src().String(), h.transport.Src().String(), h.net.Dst().String(), h.transport.Dst().String())
	tlsTaintedMu.Lock()
	delete(tlsTainted, key)
	tlsTaintedMu.Unlock()
}

// isResponseToTaintedConnection checks, from the server→client stream's
// perspective, whether the corresponding client→server stream was tainted by
// TLS bytes.
func (h *httpStream) isResponseToTaintedConnection() bool {
	// Reverse src/dst — the request stream's key uses client-first ordering.
	key := tlsTaintKey(h.net.Dst().String(), h.transport.Dst().String(), h.net.Src().String(), h.transport.Src().String())
	tlsTaintedMu.Lock()
	defer tlsTaintedMu.Unlock()
	return tlsTainted[key]
}

// parseResponseSafely parses an HTTP response from buf. It handles HEAD
// responses (which advertise Content-Length but send no body) by peeking after
// the headers — if the next bytes look like another HTTP/x.y status line, the
// response had no body. This avoids the cross-stream coordination dance that
// http.ReadResponse would otherwise need to know whether the request was HEAD.
func parseResponseSafely(buf *bufio.Reader) (*http.Response, []byte, error) {
	tp := textproto.NewReader(buf)

	statusLine, err := tp.ReadLine()
	if err != nil {
		return nil, nil, err
	}
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return nil, nil, fmt.Errorf("malformed status line: %q", statusLine)
	}
	statusCode, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid status code in %q: %w", statusLine, err)
	}
	statusText := parts[1]
	if len(parts) >= 3 {
		statusText = parts[1] + " " + parts[2]
	}

	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, nil, err
	}
	headers := http.Header(mimeHeader)

	resp := &http.Response{
		Proto:      parts[0],
		StatusCode: statusCode,
		Status:     statusText,
		Header:     headers,
	}

	// Status codes that, per RFC, never have a body.
	if statusCode < 200 || statusCode == 204 || statusCode == 304 {
		return resp, nil, nil
	}

	// Chunked encoding: read chunks via stdlib helper.
	if isChunked(headers.Get("Transfer-Encoding")) {
		body, err := io.ReadAll(httputil.NewChunkedReader(buf))
		if err != nil {
			return resp, body, err
		}
		// httputil.NewChunkedReader stops at the 0-length chunk; consume the
		// trailing CRLF (and any trailers) so the next response is at buf head.
		_, _ = tp.ReadMIMEHeader()
		return resp, body, nil
	}

	contentLengthStr := headers.Get("Content-Length")
	if contentLengthStr == "" {
		// No Content-Length and no chunked encoding: don't try to read a body —
		// connection-close framed bodies aren't worth chasing for our use case.
		return resp, nil, nil
	}
	contentLength, err := strconv.ParseInt(contentLengthStr, 10, 64)
	if err != nil || contentLength <= 0 {
		return resp, nil, nil
	}

	// HEAD detection: if the next bytes look like another HTTP status line,
	// the server advertised a body but didn't actually send one (HEAD response).
	if peeked, _ := buf.Peek(5); len(peeked) == 5 && string(peeked) == "HTTP/" {
		return resp, nil, nil
	}

	body := make([]byte, contentLength)
	if _, err := io.ReadFull(buf, body); err != nil {
		return resp, body, err
	}
	return resp, body, nil
}

func isChunked(te string) bool {
	for _, v := range strings.Split(te, ",") {
		if strings.EqualFold(strings.TrimSpace(v), "chunked") {
			return true
		}
	}
	return false
}

// logUnparseable synthesizes a request entry for non-HTTP bytes (e.g. a TLS
// ClientHello hitting a plain-HTTP port), so the 400 the server sends back has
// something to pair with in the dashboard.
func (h *httpStream) logUnparseable(firstBytes []byte) {
	now := time.Now()
	timestamp := now.Format("2006-01-02 15:04:05")

	method := "RAW"
	description := "Unparseable request bytes"

	hexPreview := fmt.Sprintf("First %d bytes (hex): % x", len(firstBytes), firstBytes)

	fmt.Printf("┌─ NON-HTTP DATA [%s]\n", timestamp)
	fmt.Printf("├─ Type: %s\n", method)
	fmt.Printf("├─ Note: %s\n", description)
	fmt.Printf("├─ Connection: %s:%s → %s:%s\n", h.net.Src(), h.transport.Src(), h.net.Dst(), h.transport.Dst())
	fmt.Printf("└─ %s\n", hexPreview)
	fmt.Println()

	pairKey := fmt.Sprintf("%s:%s-%s:%s-n%d", h.net.Src(), h.transport.Src(), h.net.Dst(), h.transport.Dst(), h.seq)

	Store.Add(CapturedPacket{
		Type:        PacketRequest,
		Timestamp:   now,
		Method:      method,
		URL:         description,
		ContentType: "application/octet-stream",
		BodySize:    len(firstBytes),
		Body:        hexPreview,
		Headers:     map[string]string{},
		Protocol:    "(non-HTTP)",
		Connection:  fmt.Sprintf("%s:%s → %s:%s", h.net.Src(), h.transport.Src(), h.net.Dst(), h.transport.Dst()),
		PairKey:     pairKey,
	})
}

func (h *httpStream) logRequest(req *http.Request, bodyBytes []byte) {
	now := time.Now()
	timestamp := now.Format("2006-01-02 15:04:05")

	fmt.Printf("┌─ HTTP REQUEST [%s]\n", timestamp)
	fmt.Printf("├─ Method: %s\n", req.Method)
	fmt.Printf("├─ URL: %s\n", req.URL.String())
	fmt.Printf("├─ Host: %s\n", req.Host)
	fmt.Printf("├─ User-Agent: %s\n", req.Header.Get("User-Agent"))
	fmt.Printf("├─ Content-Type: %s\n", req.Header.Get("Content-Type"))
	fmt.Printf("├─ Content-Length: %s\n", req.Header.Get("Content-Length"))
	fmt.Printf("├─ Body Size: %d bytes\n", len(bodyBytes))
	fmt.Printf("├─ Connection: %s → %s\n", h.net.Src(), h.net.Dst())

	alreadyLoggedHeader := []string{"User-Agent", "Content-Type", "Content-Length"}

	// Show additional headers if present
	for key, values := range req.Header {
		if slices.Contains(alreadyLoggedHeader, key) {
			continue
		}

		fmt.Printf("├─ %s: %s\n", key, strings.Join(values, ", "))
	}

	fmt.Printf("├─ Body Preview: \n")
	if len(bodyBytes) > 0 {
		preview := string(bodyBytes)
		fmt.Printf("├  %s\n", strings.TrimSuffix(preview, "\n"))
	}

	fmt.Printf("└─ Protocol: %s\n", req.Proto)
	fmt.Println()

	// Store packet for web dashboard
	headers := make(map[string]string)
	for key, values := range req.Header {
		headers[key] = strings.Join(values, ", ")
	}

	// PairKey uses client:port-server:port-seq to correlate request/response.
	// The seq number distinguishes multiple pairs on the same keep-alive connection.
	pairKey := fmt.Sprintf("%s:%s-%s:%s-n%d", h.net.Src(), h.transport.Src(), h.net.Dst(), h.transport.Dst(), h.seq)

	Store.Add(CapturedPacket{
		Type:        PacketRequest,
		Timestamp:   now,
		Method:      req.Method,
		URL:         req.URL.String(),
		Host:        req.Host,
		ContentType: req.Header.Get("Content-Type"),
		BodySize:    len(bodyBytes),
		Body:        string(bodyBytes),
		Headers:     headers,
		Protocol:    req.Proto,
		Connection:  fmt.Sprintf("%s:%s → %s:%s", h.net.Src(), h.transport.Src(), h.net.Dst(), h.transport.Dst()),
		PairKey:     pairKey,
	})
}

func (h *httpStream) logResponse(resp *http.Response, bodyBytes []byte) {
	now := time.Now()
	timestamp := now.Format("2006-01-02 15:04:05")

	fmt.Printf("┌─ HTTP RESPONSE [%s]\n", timestamp)
	fmt.Printf("├─ Status: %s\n", resp.Status)
	fmt.Printf("├─ Content-Type: %s\n", resp.Header.Get("Content-Type"))
	fmt.Printf("├─ Content-Length: %s\n", resp.Header.Get("Content-Length"))
	fmt.Printf("├─ Body Size: %d bytes\n", len(bodyBytes))
	fmt.Printf("├─ Connection: %s ← %s\n", h.net.Dst(), h.net.Src())

	alreadyLoggedHeader := []string{"Content-Type", "Content-Length"}

	// Show additional headers if present
	for key, values := range resp.Header {
		if slices.Contains(alreadyLoggedHeader, key) {
			continue
		}

		fmt.Printf("├─ %s: %s\n", key, strings.Join(values, ", "))
	}

	fmt.Printf("├─ Body Preview: \n")
	if len(bodyBytes) > 0 {
		preview := string(bodyBytes)
		fmt.Printf("├  %s\n", strings.TrimSuffix(preview, "\n"))
	}

	fmt.Printf("└─ Protocol: %s\n", resp.Proto)
	fmt.Println()

	// Store packet for web dashboard
	headers := make(map[string]string)
	for key, values := range resp.Header {
		headers[key] = strings.Join(values, ", ")
	}

	// PairKey uses client:port-server:port-seq to correlate request/response (same as request).
	pairKey := fmt.Sprintf("%s:%s-%s:%s-n%d", h.net.Dst(), h.transport.Dst(), h.net.Src(), h.transport.Src(), h.seq)

	Store.Add(CapturedPacket{
		Type:        PacketResponse,
		Timestamp:   now,
		Status:      resp.Status,
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		BodySize:    len(bodyBytes),
		Body:        string(bodyBytes),
		Headers:     headers,
		Protocol:    resp.Proto,
		Connection:  fmt.Sprintf("%s:%s ← %s:%s", h.net.Dst(), h.transport.Dst(), h.net.Src(), h.transport.Src()),
		PairKey:     pairKey,
	})
}
