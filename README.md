This is very similar to GenericPotato - I referenced it heavily while researching. 

Gotato starts a named pipe under \\\\.\\pipe\\test and waits for input. Once a client has connected Gotato will attempt to steal their token and impersonate them.
Able to trick a process running as SYSTEM into interacting with the pipe? You're now SYSTEM.

Same as the rest of the potato family this requires SeImpersonate.

https://user-images.githubusercontent.com/7650862/120907787-f92d1a80-c653-11eb-8a74-fba79b43ede0.mp4
