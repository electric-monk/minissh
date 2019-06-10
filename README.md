# minissh

A small SSH client, with no dependencies.

## Intention

Whilst primarily an encryption learning exercise, this was also designed to be a library that could be embedded within an application, or possibly even run on a microcontroller. Both the functionality and communications layer are modular, so it could run over TCP, RS232 or whatever agnostically.

## To use

Though it's plain C++, it was developed on MacOS X, so an Xcode project is provided. It should build a demo SSH client that will allow logging into an SSH server.

## Next steps

- Currently it uses some Objective C-style memory management, when C++-style smart pointers would be better. However, in order to be as portable as possible, it does not use STL, so the smart pointers will need to be implemented manually.
- Key storage, which is required for server support (which in itself should be trivial as most of the client code will also function in server mode)

