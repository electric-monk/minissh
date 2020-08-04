//
//  TestNetwork.h
//  minissh
//
//  Created by Colin David Munro on 3/08/2020.
//  Copyright © 2020 MICE Software. All rights reserved.
//

#pragma once

#include "Client.h"
#include "Session.h"

class BaseFD
{
public:
    static void Run(void);
    
protected:
    virtual void OnEvent(void) = 0;
    
    BaseFD();
    virtual ~BaseFD();
    
    BaseFD *_last, *_next;
    
    int _fd;
};

class Stdin : public BaseFD
{
public:
    Stdin(minissh::Core::Session *session);
protected:
    void OnEvent(void) override;
private:
    minissh::Core::Session *_session;
};

class BaseSocket : public BaseFD
{
public:
    ~BaseSocket();
};

class Socket : private BaseSocket, public minissh::Core::Client::IDelegate
{
public:
    Socket(const char *host, unsigned short port);

    void Send(const void *data, minissh::UInt32 length) override;
    void Failed(minissh::Core::Client::PanicReason reason) override;
    
    minissh::Transport::Transport *transport;
    std::shared_ptr<minissh::Core::Session> session;
    
protected:
    void OnEvent(void) override;
};
    
    int _sock;
};
