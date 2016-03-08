//
//  SshNumbers.h
//  minissh
//
//  Created by Colin David Munro on 18/01/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#ifndef minissh_SshNumbers_h
#define minissh_SshNumbers_h

enum {
    SSH_MSG_DISCONNECT = 1,
    SSH_MSG_IGNORE = 2,
    SSH_MSG_UNIMPLEMENTED = 3,
    SSH_MSG_DEBUG = 4,
    SSH_MSG_SERVICE_REQUEST = 5,
    SSH_MSG_SERVICE_ACCEPT = 6,
    
    SSH_MSG_KEXINIT = 20,
    SSH_MSG_NEWKEYS = 21,
    
    SSH_MSG_KEXDH_INIT = 30,    // from client
    SSH_MSG_KEXDH_REPLY = 31,   // from server
    
    SSH_MSG_USERAUTH_REQUEST = 50,  // from client
    SSH_MSG_USERAUTH_FAILURE = 51,  // from server
    SSH_MSG_USERAUTH_SUCCESS = 52,  // from server
    SSH_MSG_USERAUTH_BANNER = 53,   // from server
    
    SSH_MSG_USERAUTH_PASSWD_CHANGEREQ = 60, // from server

    SSH_MSG_CHANNEL_OPEN = 90,
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91,
    SSH_MSG_CHANNEL_OPEN_FAILURE = 92,
    SSH_MSG_CHANNEL_WINDOW_ADJUST = 93,
    SSH_MSG_CHANNEL_DATA = 94,
    SSH_MSG_CHANNEL_EXTENDED_DATA = 95,
    SSH_MSG_CHANNEL_EOF = 96,
    SSH_MSG_CHANNEL_CLOSE = 97,
    SSH_MSG_CHANNEL_REQUEST = 98,
    SSH_MSG_CHANNEL_SUCCESS = 99,
    SSH_MSG_CHANNEL_FAILURE = 100,
};

#endif
