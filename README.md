This is very similar to GenericPotato - I referenced it heavily while researching. 

Gotato starts a named pipe or web server and waits for input. Once a client has connected Gotato will attempt to steal their token and impersonate them.
Able to trick a process running as SYSTEM into interacting with the pipe or web server? You're now SYSTEM.

Same as the rest of the potato family this requires SeImpersonate.

```
Usage: gotato -m [http|pipe] [-p PORT] [-n PIPE_NAME]
  -h    Print this help menu
  -m string
        Mode \[http|pipe] (default "pipe")
  -n string
        Pipe name (default "mal")
  -p int
        HTTP server port (default 4644)
```

https://user-images.githubusercontent.com/7650862/121087215-ab3f2080-c7d3-11eb-82c7-14cef4ecc80b.mp4

https://user-images.githubusercontent.com/7650862/120907787-f92d1a80-c653-11eb-8a74-fba79b43ede0.mp4
