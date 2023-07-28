package main

import (
	"bytes"
	"context"
	"encoding/base32"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cretz/bine/tor"
	"github.com/cretz/bine/torutil/ed25519"
	"golang.org/x/crypto/sha3"
)

var key = "demo7hvlzi54qfid3n2i3xkrzhpma3hl6njljoymv47te6kckqfin6ad.key"

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	// Start tor with default config (can set start conf's DebugWriter to os.Stdout for debug logs)
	fmt.Println("Starting and registering onion service, please wait a couple of minutes...")
	t, err := tor.Start(nil, nil)
	if err != nil {
		return err
	}
	defer t.Close()
	// Add a handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, Dark World!"))
	})
	// Wait at most a few minutes to publish the service
	listenCtx, listenCancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer listenCancel()

	keyBytes, err := os.ReadFile(key)
	if err != nil {
		panic(err)
	}
	key := ed25519.PrivateKey(keyBytes)
	addr := encodePublicKey(key.PublicKey())
	fmt.Println("Found onion addr from key", addr)
	fmt.Println("Starting the tor server...")

	onion, err := t.Listen(listenCtx, &tor.ListenConf{Key: key, LocalPort: 8080, RemotePorts: []int{80}})
	if err != nil {
		return err
	}
	defer onion.Close()
	// Serve on HTTP
	fmt.Printf("Open Tor browser and navigate to http://%v.onion\n", onion.ID)
	return http.Serve(onion, nil)
}

func encodePublicKey(publicKey ed25519.PublicKey) string {

	// checksum = H(".onion checksum" || pubkey || version)
	var checksumBytes bytes.Buffer
	checksumBytes.Write([]byte(".onion checksum"))
	checksumBytes.Write([]byte(publicKey))
	checksumBytes.Write([]byte{0x03})
	checksum := sha3.Sum256(checksumBytes.Bytes())

	// onion_address = base32(pubkey || checksum || version)
	var onionAddressBytes bytes.Buffer
	onionAddressBytes.Write([]byte(publicKey))
	onionAddressBytes.Write([]byte(checksum[:2]))
	onionAddressBytes.Write([]byte{0x03})
	onionAddress := base32.StdEncoding.EncodeToString(onionAddressBytes.Bytes())

	return strings.ToLower(onionAddress)
}
