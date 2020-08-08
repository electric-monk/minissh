//
//  Server.hpp
//  libminissh
//
//  Created by Colin David Munro on 1/08/2020.
//  Copyright © 2020 MICE Software. All rights reserved.
//

#pragma once

#include "Transport.h"

namespace minissh::Core {

/**
 * Implementation of an SSH server.
 */
class Server : public Transport::Transport
{
public:
    /**
     * Interface to provide a service for SSH.
     */
    class IServiceProvider : public minissh::Transport::IMessageHandler
    {
    public:
        virtual void ServiceRequested() = 0;
    };
    
    /**
     * Interface for a service which can provide services.
     */
    class IServiceHandler : public minissh::Transport::IMessageHandler
    {
    public:
        virtual void RegisterService(const std::string& name, std::shared_ptr<IServiceProvider> provider) = 0;
    };
    
    Server(Maths::IRandomSource& source);

    std::shared_ptr<IServiceHandler> DefaultServiceHandler(void);
};
    
} // namespace minissh::Core
