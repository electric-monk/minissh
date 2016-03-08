//
//  DiffieHellman.h
//  minissh
//
//  Created by Colin David Munro on 31/01/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#ifndef __minissh__DiffieHellman__
#define __minissh__DiffieHellman__

#include "Transport.h"

class LargeNumber;

class diffieHellman : public sshKeyExchanger
{
public:
    diffieHellman(sshTransport *owner, TransportMode mode);
    
    void Start(void);
    
    void HandlePayload(sshBlob *data);
    
    virtual LargeNumber* Prime(void) = 0;
    virtual LargeNumber* Generator(void) = 0;
    
protected:
    ~diffieHellman();
    
private:
    LargeNumber *_xy;

    LargeNumber *_e, *_f;
    
    sshString *_hostKey;
    
    bool CheckRange(LargeNumber *number);
    sshString* MakeHash(void);
};

class dhGroup1 : public diffieHellman
{
public:
    class Factory : public sshConfiguration::FactoryTemplate<dhGroup1>
    {
    public:
        const char* Name(void) const
        {
            return "diffie-hellman-group1-sha1";
        }
    };
    
    dhGroup1(sshTransport *owner, TransportMode mode);
    LargeNumber* Prime(void);
    LargeNumber* Generator(void);
};

class dhGroup14 : public diffieHellman
{
public:
    class Factory : public sshConfiguration::FactoryTemplate<dhGroup14>
    {
    public:
        const char* Name(void) const
        {
            return "diffie-hellman-group14-sha1";
        }
    };

    dhGroup14(sshTransport *owner, TransportMode mode);
    LargeNumber* Prime(void);
    LargeNumber* Generator(void);
};

#endif /* defined(__minissh__DiffieHellman__) */
