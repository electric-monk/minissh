//
//  Client.cpp
//  minissh
//
//  Created by Colin David Munro on 13/02/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#include "Client.h"
#include "SshNumbers.h"
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>

namespace sshClient_Internal {
    const Byte messages[] = {SSH_MSG_SERVICE_ACCEPT};

    class Enabler : public sshClient::Enabler
    {
    public:
        Enabler(sshClient *owner)
        {
            _owner = owner;
            _owner->RegisterForPackets(this, messages, sizeof(messages) / sizeof(messages[0]));
            _pending = new sshDictionary();
            _running = false;
        }
        ~Enabler()
        {
            _owner->UnregisterForPackets(messages, sizeof(messages) / sizeof(messages[0]));
            _pending->Release();
        }
        
        void Start(void)
        {
            if (!_running) {
                _running = true;
                if (_pending->AllKeys()->Count() != 0)
                    RequestNext();
            }
        }
        
        void Request(const char *name, sshClient::Service *service)
        {
            // Add to list
            sshString *nameString = new sshString();
            nameString->AppendFormat("%s", name);
            _pending->Set(nameString, service);
            nameString->Release();
            // If necessary, trigger
            if (_running && (_pending->AllKeys()->Count() == 1))
                RequestNext();
        }
        
        void HandlePayload(sshBlob *data)
        {
            sshReader reader(data);
            if (reader.ReadByte() != SSH_MSG_SERVICE_ACCEPT)
                ;//error
            sshString *result = reader.ReadString();
            sshString *expected = _pending->AllKeys()->ItemAt(0);
            if (!result->IsEqual(expected)) {
                // error
                return;
            }
            sshClient::Service *service = (sshClient::Service*)_pending->ObjectFor(expected);
            service->Start();
            DEBUG_LOG_STATE(("Service accepted\n"));
            _pending->Set(expected, NULL);
            // TODO: tell someone it's done, so they can proceed if necessary
            if (_pending->AllKeys()->Count() != 0)
                RequestNext();
        }
        
    private:
        bool _running;
        sshClient *_owner;
        sshDictionary *_pending;
        
        void RequestNext(void)
        {
            sshBlob *message = new sshBlob();
            sshWriter writer(message);
            writer.Write(Byte(SSH_MSG_SERVICE_REQUEST));
            writer.Write(_pending->AllKeys()->ItemAt(0));
            _owner->Send(message);
            message->Release();
            
            char *temp = new char[_pending->AllKeys()->ItemAt(0)->Length() + 1];
            memcpy(temp, _pending->AllKeys()->ItemAt(0)->Value(), _pending->AllKeys()->ItemAt(0)->Length());
            temp[_pending->AllKeys()->ItemAt(0)->Length()] = 0;
            DEBUG_LOG_STATE(("Requesting basic service: %s\n", temp));
            delete[] temp;
        }
    };
}

sshClient::sshClient()
{
    _enabler = new sshClient_Internal::Enabler(this);
}

sshClient::~sshClient()
{
    _enabler->Release();
}

sshClient::Enabler* sshClient::DefaultEnabler(void)
{
    return _enabler;
}

void sshClient::KeysChanged(void)
{
    sshTransport::KeysChanged();
    ((sshClient_Internal::Enabler*)_enabler)->Start();
}
