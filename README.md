This is very similar to GenericPotato - I heavily referenced it while researching. 

Gotato starts a named pipe under \\\\.\\pipe\\test and waits for input. Once a client has connected Gotato will attempt to steal their token and impersonate them.
Able to trick a process running as SYSTEM into interacting with the pipe? You're now SYSTEM.

Same as the rest of the potato family this requires SeImpersonate.