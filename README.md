# minissh

A small SSH client, with no dependencies.

## Intention

Whilst primarily an encryption learning exercise, this was also designed to be a library that could be embedded within an application, or possibly even run on a microcontroller. Both the functionality and communications layer are modular, so it could run over TCP, RS232 or whatever agnostically.

For this reason the code has no library dependencies whatsoever (though it currently depends on STL, which ideally is provided with your compiler), and expects you to provide a secure random source and I/O. On the flip side, it does not require threads and you can also open/close streams within the session freely.

## To use

Though it's plain C++, it was developed on MacOS X, so an Xcode project is provided. It should build a demo SSH client that will allow logging into an SSH server.

## Next steps

- It's been updated to use STL smart pointers and strings, however this has increased the binary size by ~200K. Custom implementations may help for embedded purposes. It's also C++17, which may be a bit new for some purposes. On the plus side, the code is more clear to follow.
- Blob class needs to be upgraded to be more efficient, by internally sharing pointers/etc.
