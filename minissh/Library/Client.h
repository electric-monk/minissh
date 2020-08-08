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

/**
 * Class implementing SSH client-specific parts of the transport.
 */
class Client : public Transport::Transport
{
public:
    /**
     * Interface for an SSH service client.
     */
    class IService : public minissh::Transport::IMessageHandler
    {
    public:
        virtual void Start(void) = 0;
    };

    /**
     * Interface for an SSH service enabler, which is used to request a specific service.
     */
    class IEnabler : public minissh::Transport::IMessageHandler
    {
    public:
        /**
         * Request a service from the server with the given name. If successful, service->Start() is called.
         */
        virtual void Request(const std::string& name, IService* service) = 0;
    };
    
    Client(Maths::IRandomSource& source);
    
    std::shared_ptr<IEnabler> DefaultEnabler(void);  // Doesn't do any authentication/etc., just asks for it

protected:
    void KeysChanged(void) override;
    
private:
    std::shared_ptr<IEnabler> _enabler;
};

} // namespace minissh::Core
