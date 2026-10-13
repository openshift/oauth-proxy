# wsutil

Like `net/http/httputil` but for WebSockets.

[![GoDoc](https://godoc.org/github.com/yhat/wsutil?status.svg)](https://godoc.org/github.com/yhat/wsutil)

## A Reverse Proxy Example

```go
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/yhat/wsutil"
	"golang.org/x/net/websocket"
)

func main() {
	backend := ":8001"
	proxy := ":8002"

	// an webscket echo server
	backendHandler := websocket.Handler(func(ws *websocket.Conn) {
		io.Copy(ws, ws)
	})

	// make a proxy pointing at that backend url
	backendURL := &url.URL{Scheme: "ws://", Host: backend}
	p := wsutil.NewSingleHostReverseProxy(backendURL)

	// run both servers and give them a second to start up
	go http.ListenAndServe(backend, backendHandler)
	go http.ListenAndServe(proxy, p)
	time.Sleep(1 * time.Second)

	// connect to the proxy
	origin := "http://localhost/"
	ws, err := websocket.Dial("ws://"+proxy, "", origin)
	if err != nil {
		log.Fatal(err)
	}

	// send a message along the websocket
	msg := []byte("isn't yhat awesome?")
	if _, err := ws.Write(msg); err != nil {
		log.Fatal(err)
	}

	// read the response from the proxy
	resp := make([]byte, 4096)
	if n, err := ws.Read(resp); err != nil {
		log.Fatal(err)
	} else {
		fmt.Printf("%s\n", resp[:n])
	}
}
```
