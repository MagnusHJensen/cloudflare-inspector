package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct{}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go hstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)
	for {
		// Peek at the first line to determine if it's a request or response
		line, _, err := buf.ReadLine()
		if err == io.EOF {
			return
		} else if err != nil {
			log.Println("Error reading stream", h.net, h.transport, ":", err)
			continue
		}

		lineStr := string(line)

		// Check if it's an HTTP request (starts with method)
		if h.isHTTPRequest(lineStr) {
			// Put the line back and read as request
			fullLine := lineStr + "\r\n"
			reader := io.MultiReader(strings.NewReader(fullLine), buf)
			req, err := http.ReadRequest(bufio.NewReader(reader))
			if err != nil {
				log.Println("Error reading request", h.net, h.transport, ":", err)
				continue
			}

			// Read the actual body content
			bodyBytes, err := io.ReadAll(req.Body)
			if err != nil {
				log.Println("Error reading request body", h.net, h.transport, ":", err)
				bodyBytes = []byte{}
			}
			req.Body.Close()

			h.logRequest(req, bodyBytes)
		} else if h.isHTTPResponse(lineStr) {
			// Put the line back and read as response
			fullLine := lineStr + "\r\n"
			reader := io.MultiReader(strings.NewReader(fullLine), buf)
			resp, err := http.ReadResponse(bufio.NewReader(reader), nil)
			if err != nil {
				log.Println("Error reading response", h.net, h.transport, ":", err)
				continue
			}

			// Read the actual body content
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Println("Error reading response body", h.net, h.transport, ":", err)
				bodyBytes = []byte{}
			}
			resp.Body.Close()

			h.logResponse(resp, bodyBytes)
		} else {
			// Skip unknown data
			continue
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

func (h *httpStream) logRequest(req *http.Request, bodyBytes []byte) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")

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

		fmt.Printf("├─ %s: %s\n", key, values)
	}

	fmt.Printf("├─ Body Preview: \n")
	if len(bodyBytes) > 0 {
		preview := string(bodyBytes)
		fmt.Printf("├  %s\n", strings.TrimSuffix(preview, "\n"))
	}

	fmt.Printf("└─ Protocol: %s\n", req.Proto)
	fmt.Println()
}

func (h *httpStream) logResponse(resp *http.Response, bodyBytes []byte) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")

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

		fmt.Printf("├─ %s: %s\n", key, values)
	}

	fmt.Printf("├─ Body Preview: \n")
	if len(bodyBytes) > 0 {
		preview := string(bodyBytes)
		fmt.Printf("├  %s\n", strings.TrimSuffix(preview, "\n"))
	}

	fmt.Printf("└─ Protocol: %s\n", resp.Proto)
	fmt.Println()
}
