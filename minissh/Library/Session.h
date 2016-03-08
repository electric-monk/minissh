//
//  Session.h
//  minissh
//
//  Created by Colin David Munro on 20/02/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#ifndef __minissh__Session__
#define __minissh__Session__

#include "Connection.h"

class sshSession : public sshConnection::sshChannel
{
public:
    sshSession(sshConnection *owner);
    
    sshBlob* OpenInfo(sshString **nameOut, UInt32 *packetSize, UInt32 *windowSize);
    void Opened(sshBlob *data);
    void OpenFailed(UInt32 reason, sshString *message, sshString *languageTag);
    
    void ReceivedClose(void);
    void ReceivedData(sshBlob *data);
    void ReceivedExtendedData(UInt32 type, sshBlob *data);
    void ReceivedRequestResponse(bool success);
    
    void Send(const char *keystrokes, UInt32 length);
    
private:
    bool _shell;
};

#endif /* defined(__minissh__Session__) */
