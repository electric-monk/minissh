//
//  SshNumbers.h
//  minissh
//
//  Created by Colin David Munro on 18/01/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#pragma once

#include "Types.h"

enum SSHMessages : minissh::Byte {
    DISCONNECT = 1,
    IGNORE = 2,
    UNIMPLEMENTED = 3,
    DEBUGMSG = 4,
    SERVICE_REQUEST = 5,
    SERVICE_ACCEPT = 6,
    
    KEXINIT = 20,
    NEWKEYS = 21,
    
    KEXDH_INIT = 30,    // from client
    KEXDH_REPLY = 31,   // from server
    
    USERAUTH_REQUEST = 50,  // from client
    USERAUTH_FAILURE = 51,  // from server
    USERAUTH_SUCCESS = 52,  // from server
    USERAUTH_BANNER = 53,   // from server
    
    USERAUTH_PASSWD_CHANGEREQ = 60, // from server

    CHANNEL_OPEN = 90,
    CHANNEL_OPEN_CONFIRMATION = 91,
    CHANNEL_OPEN_FAILURE = 92,
    CHANNEL_WINDOW_ADJUST = 93,
    CHANNEL_DATA = 94,
    CHANNEL_EXTENDED_DATA = 95,
    CHANNEL_EOF = 96,
    CHANNEL_CLOSE = 97,
    CHANNEL_REQUEST = 98,
    CHANNEL_SUCCESS = 99,
    CHANNEL_FAILURE = 100,
};
