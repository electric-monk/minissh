# minissh

A small SSH client and server, with no dependencies.

The client will allow you to connect and use an SSH server somewhat haphazardly (e.g. it always says it's a vt100, and Control-C will kill the client, not send Ctrl-C to the server). The client can use OpenSSH-style private keys for the public key authentication mechanism, like the ones found in ~/.ssh/

The server will send a nice banner, let you log in with any username/password, and then send anything you type back with a message. It will also accept any public key authentication, to confirm that logic, but doesn't check a local store to make sure the public key is the expected one.

## Intention

Whilst primarily an encryption learning exercise, this was also designed to be a library that could be embedded within an application, or possibly even run on a microcontroller. Both the functionality and communications layer are modular, so it could run over TCP, RS232 or whatever agnostically.

For this reason the code has no library dependencies whatsoever (though it currently depends on STL, which ideally is provided with your compiler), and expects you to provide a secure random source and I/O. On the flip side, it does not require threads and you can also open/close streams within the session freely.

## To use

Though it's plain C++, it was developed on MacOS X, so an Xcode project is provided. It should build a demo SSH client that will allow logging into an SSH server. Some basic makefiles are also provided so as to allow people to play with it outside Xcode.

## Next steps

- It's been updated to use STL smart pointers and strings, however this has increased the binary size by ~200K. Custom implementations may help for embedded purposes. It's also C++17, which may be a bit new for some purposes. On the plus side, the code is more clear to follow.
- Blob class needs to be upgraded to be more efficient, by internally sharing pointers/etc.
- Faster prime generation. Currently it uses a fairly slow, accurate method, so for server mode it'll spend a while generating the host key and even the client will spend a few seconds computing a prime.
