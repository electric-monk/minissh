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

class SocketTest : public minissh::Core::Client::IDelegate
{
public:
    SocketTest(const char *host, unsigned short port);
    
    void Send(const void *data, minissh::UInt32 length) override;
    void Failed(minissh::Core::Client::PanicReason reason) override;
    
    void Run(void);
    
    minissh::Transport::Transport *transport;
    std::shared_ptr<minissh::Core::Session> session;
    
protected:
    ~SocketTest();
    
    int _sock;
};
