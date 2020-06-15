//
//  Client.cpp
//  minissh
//
//  Created by Colin David Munro on 13/02/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#include "Client.h"
#include "SshNumbers.h"
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>

namespace minissh::Core {

namespace {
    
    const Byte messages[] = {SERVICE_ACCEPT};

    class DefaultEnablerImpl : public Client::Enabler
    {
    public:
        DefaultEnablerImpl(Client& owner)
        :_owner(owner)
        {
            _owner.RegisterForPackets(this, messages, sizeof(messages) / sizeof(messages[0]));
            _running = false;
        }
        ~DefaultEnablerImpl()
        {
            _owner.UnregisterForPackets(messages, sizeof(messages) / sizeof(messages[0]));
        }
        
        void Start(void)
        {
            if (!_running) {
                _running = true;
                if (_pending.size() != 0)
                    RequestNext();
            }
        }
        
        void Request(const std::string& name, Client::Service* service) override
        {
            // Add to list
            _pending.push_back({name, service});
            // If necessary, trigger
            if (_running && (_pending.size() == 1))
                RequestNext();
        }
        
        void HandlePayload(Types::Blob data) override
        {
            Types::Reader reader(data);
            if (reader.ReadByte() != SERVICE_ACCEPT)
                ;//error
            std::string result = reader.ReadString().AsString();
            RequestRecord &record = _pending.front();
            if (result.compare(record.expected) != 0) {
                // error
                return;
            }
            record.service->Start();
            DEBUG_LOG_STATE(("Service accepted\n"));
            _pending.erase(_pending.begin());
            // TODO: tell someone it's done, so they can proceed if necessary
            if (_pending.size() != 0)
                RequestNext();
        }
        
    private:
        struct RequestRecord {
            std::string expected;
            Client::Service *service;
        };
        
        bool _running;
        Client& _owner;
        std::vector<RequestRecord> _pending;
        
        void RequestNext(void)
        {
            Types::Blob message;
            Types::Writer writer(message);
            writer.Write(Byte(SERVICE_REQUEST));
            writer.WriteString(_pending.front().expected);
            _owner.Send(message);
            
            DEBUG_LOG_STATE(("Requesting basic service: %s\n", _pending.front().expected.c_str()));
        }
    };
    
} // namespace

Client::Client(Maths::RandomSource& source)
:Transport(source), _enabler(std::make_shared<DefaultEnablerImpl>(*this))
{
}

std::shared_ptr<Client::Enabler> Client::DefaultEnabler(void)
{
    return _enabler;
}

void Client::KeysChanged(void)
{
    Transport::KeysChanged();
    std::dynamic_pointer_cast<DefaultEnablerImpl>(_enabler)->Start();
}

} // namespace minissh::Core
