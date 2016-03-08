//
//  Session.cpp
//  minissh
//
//  Created by Colin David Munro on 20/02/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#include <stdio.h>
#include "Session.h"

sshSession::sshSession(sshConnection *owner)
:sshConnection::sshChannel(owner)
{
    _shell = false;
}

sshBlob* sshSession::OpenInfo(sshString **nameOut, UInt32 *packetSize, UInt32 *windowSize)
{
    *nameOut = new sshString();
    (*nameOut)->AppendFormat("session");
    (*nameOut)->Autorelease();
    return NULL;
}

void sshSession::Opened(sshBlob *data)
{
    sshString *request = new sshString();
    request->AppendFormat("pty-req");
    sshBlob *parameters = new sshBlob();
    sshWriter writer(parameters);
    sshString *terminalType = new sshString();
    terminalType->AppendFormat("vt100");
    writer.Write(terminalType);
    terminalType->Release();
    writer.Write(UInt32(80));
    writer.Write(UInt32(24));
    writer.Write(UInt32(640));
    writer.Write(UInt32(480));
    sshString *terminalModes = new sshString();
    terminalModes->AppendFormat("%c", 0);
    writer.Write(terminalModes);
    terminalModes->Release();
    Request(request, true, parameters);
    request->Release();
    parameters->Release();
}

void sshSession::OpenFailed(UInt32 reason, sshString *message, sshString *languageTag)
{
    printf("Failed to create session: %i: %s\n", reason, message->Value());
}

void sshSession::ReceivedRequestResponse(bool success)
{
    if (!success) {
        printf("Failed to open TTY\n");
        return;
    }
    if (!_shell) {
        _shell = true;
        sshString *request = new sshString();
        request->AppendFormat("shell");
        Request(request, false, NULL);
        request->Release();
    }
}

void sshSession::ReceivedClose(void)
{
    printf("Session closed\n");
}

void sshSession::ReceivedData(sshBlob *data)
{
    for (int i = 0; i < data->Length(); i++)
        printf("%c", data->Value()[i]);
    fflush(stdout);
}

void sshSession::ReceivedExtendedData(UInt32 type, sshBlob *data)
{
    for (int i = 0; i < data->Length(); i++)
        printf("%c", data->Value()[i]);
    fflush(stdout);
}

void sshSession::Send(const char *keystrokes, UInt32 length)
{
    sshBlob *blob = new sshBlob();
    blob->Append((Byte*)keystrokes, length);
    sshChannel::Send(blob);
    blob->Release();
}
