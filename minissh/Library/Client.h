//
//  Client.h
//  minissh
//
//  Created by Colin David Munro on 13/02/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#pragma once

#include "Transport.h"

namespace minissh::Core {

class Client : public Transport::Transport
{
public:
    class Enabler;
    
    class Service : public minissh::Transport::MessageHandler
    {
    public:
        virtual void Start(void) = 0;
    };

    class Enabler : public minissh::Transport::MessageHandler
    {
    public:
        virtual void Request(const std::string& name, Service* service) = 0;
    };
    
    Client(Maths::RandomSource& source);
    
    std::shared_ptr<Enabler> DefaultEnabler(void);  // Doesn't do any authentication/etc., just asks for it

protected:
    void KeysChanged(void);
    
private:
    std::shared_ptr<Enabler> _enabler;
};

} // namespace minissh::Core
