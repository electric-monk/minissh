//
//  SSH_RSA.h
//  minissh
//
//  Created by Colin David Munro on 3/02/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#ifndef __minissh__SSH_RSA__
#define __minissh__SSH_RSA__

#include "Transport.h"
#include "RSA.h"

class SSH_RSA : public sshHostKeyAlgorithm
{
public:
    SSH_RSA(sshTransport *owner, TransportMode mode);
    bool Confirm(sshString *hostKey);
    bool Verify(sshString *hostKey, sshString *signature, sshString *message);

    class Factory : public sshConfiguration::FactoryTemplate<SSH_RSA>
    {
    public:
        const char* Name(void) const
        {
            return "ssh-rsa";
        }
    };
};

#endif /* defined(__minissh__SSH_RSA__) */
