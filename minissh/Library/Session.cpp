//
//  Session.cpp
//  minissh
//
//  Created by Colin David Munro on 20/02/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#include <stdio.h>
#include "Session.h"

namespace minissh::Core {

Session::Session(Connection& owner)
:Connection::AChannel(owner)
{
    _shell = false;
}

std::optional<Types::Blob> Session::OpenInfo(std::string &nameOut, UInt32 &packetSize, UInt32 &windowSize)
{
    nameOut = "session";
    return {};
}

void Session::Opened(Types::Blob data)
{
    Types::Blob parameters;
    Types::Writer writer(parameters);
    writer.WriteString("vt100");
    writer.Write(UInt32(80));
    writer.Write(UInt32(24));
    writer.Write(UInt32(640));
    writer.Write(UInt32(480));
    char terminalModes[] = {0};
    writer.WriteString(std::string(terminalModes, sizeof(terminalModes)));
    Request("pty-req", true, parameters);
}

void Session::OpenFailed(UInt32 reason, const std::string& message, const std::string& languageTag)
{
    printf("Failed to create session: %i: %s\n", reason, message.c_str());
}

void Session::ReceivedRequestResponse(bool success)
{
    if (!success) {
        printf("Failed to open TTY\n");
        return;
    }
    if (!_shell) {
        _shell = true;
        Request("shell", false, std::nullopt);
    }
}

void Session::ReceivedClose(void)
{
    printf("Session closed\n");
}

void Session::ReceivedData(Types::Blob data)
{
    for (int i = 0; i < data.Length(); i++)
        printf("%c", data.Value()[i]);
    fflush(stdout);
}

void Session::ReceivedExtendedData(UInt32 type, Types::Blob data)
{
    for (int i = 0; i < data.Length(); i++)
        printf("%c", data.Value()[i]);
    fflush(stdout);
}

void Session::Send(const char *keystrokes, UInt32 length)
{
    AChannel::Send(Types::Blob((Byte*)keystrokes, length));
}

} // namespace minissh::Core
