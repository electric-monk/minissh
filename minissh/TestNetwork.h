//
//  TestNetwork.h
//  minissh
//
//  Created by Colin David Munro on 3/08/2020.
//  Copyright © 2020 MICE Software. All rights reserved.
//

#pragma once

#include "Client.h"
#include "RSA.h"

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

class BaseSocket : public BaseFD
{
public:
    ~BaseSocket();
};

class Socket : private BaseSocket, public minissh::Core::Client::IDelegate
{
public:
    Socket(const char *host, unsigned short port);
    Socket(int fd);

    void Send(const void *data, minissh::UInt32 length) override;
    void Failed(minissh::Core::Client::PanicReason reason) override;
    std::shared_ptr<minissh::Files::Format::IKeyFile> GetHostKey(void) override;
    
    minissh::Transport::Transport *transport;
    std::shared_ptr<minissh::RSA::KeySet> hostKey;
    
protected:
    void OnEvent(void) override;
};

class Listener : private BaseSocket
{
public:
    Listener(unsigned short port);
    
    virtual void OnAccepted(std::shared_ptr<Socket> connection) = 0;
    
protected:
    void OnEvent(void) override;
};
