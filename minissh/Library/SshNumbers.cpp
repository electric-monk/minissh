//
//  SshNumbers.cpp
//  minissh
//
//  Created by Colin David Munro on 01/08/2020.
//  Copyright (c) 2020 MICE Software. All rights reserved.
//
#include "SshNumbers.h"

#define STRING(x)   case x: return #x

std::string StringForSSHNumber(SSHMessages number)
{
    switch (number) {
        STRING(DISCONNECT);
        STRING(IGNORE);
        STRING(UNIMPLEMENTED);
        STRING(DEBUGMSG);
        STRING(SERVICE_REQUEST);
        STRING(SERVICE_ACCEPT);
        STRING(KEXINIT);
        STRING(NEWKEYS);
        STRING(KEXDH_INIT);
        STRING(KEXDH_REPLY);
        STRING(USERAUTH_REQUEST);
        STRING(USERAUTH_FAILURE);
        STRING(USERAUTH_SUCCESS);
        STRING(USERAUTH_BANNER);
        STRING(USERAUTH_PASSWD_CHANGEREQ);
        STRING(CHANNEL_OPEN);
        STRING(CHANNEL_OPEN_CONFIRMATION);
        STRING(CHANNEL_OPEN_FAILURE);
        STRING(CHANNEL_WINDOW_ADJUST);
        STRING(CHANNEL_DATA);
        STRING(CHANNEL_EXTENDED_DATA);
        STRING(CHANNEL_EOF);
        STRING(CHANNEL_CLOSE);
        STRING(CHANNEL_REQUEST);
        STRING(CHANNEL_SUCCESS);
        STRING(CHANNEL_FAILURE);
        default:
            return "Unknown";
    };
}
