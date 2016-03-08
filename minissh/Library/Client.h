//
//  Client.h
//  minissh
//
//  Created by Colin David Munro on 13/02/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#ifndef __minissh__Client__
#define __minissh__Client__

#include "Transport.h"

class sshClient : public sshTransport
{
public:
    class Enabler;
    
    class Service : public sshMessageHandler
    {
    public:
        virtual void Start(void) = 0;
    };

    class Enabler : public sshMessageHandler
    {
    public:
        virtual void Request(const char *name, Service *service) = 0;
    };
    
    sshClient();
    ~sshClient();
    
    Enabler* DefaultEnabler(void);  // Doesn't do any authentication/etc., just asks for it

protected:
    void KeysChanged(void);
    
private:
    Enabler *_enabler;
};

#endif /* defined(__minissh__Client__) */
