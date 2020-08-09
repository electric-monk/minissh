//
//  Server.cpp
//  libminissh
//
//  Created by Colin David Munro on 1/08/2020.
//  Copyright © 2020 MICE Software. All rights reserved.
//

#include "Server.h"
#include "SshNumbers.h"

namespace minissh::Core {
    
namespace {

const Byte messages[] = {SERVICE_REQUEST};

class DefaultHandler : public Server::IServiceHandler
{
private:
    Server &_owner;
    std::map<std::string, Server::IServiceProvider*> _services;
public:
    DefaultHandler(Server& owner)
    :_owner(owner)
    {
        _owner.RegisterForPackets(this, messages, sizeof(messages) / sizeof(messages[0]));
    }
    
    ~DefaultHandler()
    {
        _owner.UnregisterForPackets(messages, sizeof(messages) / sizeof(messages[0]));
    }
    
    void RegisterService(const std::string& name, Server::IServiceProvider* provider) override
    {
        if (provider == nullptr)
            _services.erase(name);
        else
            _services[name] = provider;
    }
    
    void HandlePayload(Types::Blob data) override
    {
        Types::Reader reader(data);
        switch (reader.ReadByte()) {
            case SERVICE_REQUEST:
            {
                std::string serviceName = reader.ReadString().AsString();
                DEBUG_LOG_STATE(("Received service request: %s\n", serviceName.c_str()));
                auto service = _services.find(serviceName);
                if (service != _services.end()) {
                    // Reply accepted
                    Types::Blob response;
                    Types::Writer writer(response);
                    writer.Write(SERVICE_ACCEPT);
                    writer.WriteString(serviceName);
                    _owner.Send(response);
                    // Actually trigger it
                    Server::IServiceProvider *provider = service->second;
                    provider->ServiceRequested(serviceName, {});
                } else {
                    DEBUG_LOG_STATE(("Service not registered!\n"));
                    _owner.Disconnect(DISCONNECT_SERVICE_NOT_AVAILABLE);
                }
            }
                break;
            default:
                // We weren't subscribed to this?
                _owner.Panic(Server::PanicReason::InvalidMessage);
                break;
        }
    }
};

}
    
Server::Server(Maths::IRandomSource& source)
:Transport::Transport(source, ::minissh::Transport::Mode::Server), _handler(std::make_shared<DefaultHandler>(*this))
{
    
}

std::shared_ptr<Server::IServiceHandler> Server::DefaultServiceHandler(void)
{
    return _handler;
}

} // namespace minissh::Core
