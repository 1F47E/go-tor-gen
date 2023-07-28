package main

import (
	"bytes"
	"encoding/base32"
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/cretz/bine/torutil/ed25519"
	"golang.org/x/crypto/sha3"
)

func main() {
	var err error

	if len(os.Args) < 2 {
		fmt.Println("Usage: go-tor-gen <onion address regexp> like ^name")
		os.Exit(1)
	}
	addrRegexp := os.Args[1]

	re, err := regexp.Compile(addrRegexp)
	if err != nil {
		panic(err)
	}

	// create res dir
	dir := "hostnames"
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.Mkdir(dir, 0755)
		if err != nil {
			panic(err)
		}
	}

	cnt := 0
	found := 0
	cores := runtime.NumCPU()
	wg := sync.WaitGroup{}
	for i := 0; i < cores; i++ {
		wg.Add(1)
		go func() {
			for {
				rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
				keyPair, err := ed25519.GenerateKey(rnd)
				if err != nil {
					panic(err)
				}
				publicKey := keyPair.PublicKey()
				onionAddress := encodePublicKey(publicKey)
				if re.MatchString(onionAddress) {
					// MATCH!
					fmt.Printf("Found onion address %d:%s\n", found, onionAddress)
					fmt.Println("Tries:", cnt)
					// save private key
					privateKeybytes := keyPair.PrivateKey()
					keyFile := fmt.Sprintf("%s/%s", dir, onionAddress)
					err = os.WriteFile(keyFile, []byte(privateKeybytes), 0644)
					if err != nil {
						panic(err)
					}
					found++
				}
				cnt++
			}
		}()
	}
	wg.Wait()
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
