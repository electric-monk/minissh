//
//  SSH_HMAC.h
//  minissh
//
//  Created by Colin David Munro on 9/02/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#ifndef __minissh__SSH_HMAC__
#define __minissh__SSH_HMAC__

#include "Transport.h"

class HMAC_SHA1 : public sshHMACAlgorithm
{
public:
    HMAC_SHA1(sshTransport *owner, TransportMode mode);
    
    sshBlob* Generate(sshBlob *packet);
    
    int Length(void);
    
    class Factory : public sshConfiguration::FactoryTemplate<HMAC_SHA1>
    {
    public:
        const char* Name(void) const
        {
            return "hmac-sha1";
        }
    };

protected:
    ~HMAC_SHA1();
    
private:
    sshBlob *_key;
};

#endif /* defined(__minissh__SSH_HMAC__) */
