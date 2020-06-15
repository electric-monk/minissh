//
//  SshAuth.cpp
//  minissh
//
//  Created by Colin David Munro on 16/02/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#include "SshAuth.h"
#include "SshNumbers.h"
#include <stdio.h>
#include <memory.h>

namespace minissh {

namespace Client {
    const Byte messages[] = {USERAUTH_BANNER, USERAUTH_FAILURE, USERAUTH_SUCCESS};

    namespace {
        class Enabler : public Core::Client::Enabler
        {
        public:
            Enabler(AuthService& owner, Core::Client& client, Authenticator *auth)
            :_owner(owner), _client(client), _auth(auth)
            {
            }
            
            void Request(const std::string& name, Core::Client::Service* service) override
            {
                _owner.Enqueue({&_client, name, service, _auth});
            }
            
            void HandlePayload(Types::Blob data) override
            {
                // We don't use this as a message handler
            }
            
        private:
            AuthService &_owner;
            Core::Client &_client;
            Authenticator *_auth;
        };
    }

    Authenticator::Replier::Replier(Internal::AuthTask& task)
    :_task(task)
    {
    }
    
    std::string Authenticator::Replier::Name(void)
    {
        return _task._name;
    }
    
    Core::Client::Service& Client::Authenticator::Replier::Service(void)
    {
        return *_task._service;
    }
    
    void Authenticator::Replier::SendPassword(const std::string& username, const std::string& password, const std::optional<std::string>& newPassword)
    {
        Types::Blob message;
        Types::Writer writer(message);
        writer.Write(Byte(USERAUTH_REQUEST));
        writer.WriteString(username);
        writer.WriteString(Name());
        writer.WriteString("password");
        writer.Write(bool(newPassword));
        writer.WriteString(password);
        if (newPassword)
            writer.WriteString(*newPassword);
        _task._client->Send(message);
    }
    
    AuthService::AuthService(Core::Client& owner, std::shared_ptr<Core::Client::Enabler> enabler)
    :_running(false), _owner(owner), _authenticator(nullptr)
    {
        enabler->Request("ssh-userauth", this);
        _owner.RegisterForPackets(this, messages, sizeof(messages) / sizeof(messages[0]));
    }
    
    AuthService::~AuthService()
    {
        _owner.UnregisterForPackets(messages, sizeof(messages) / sizeof(messages[0]));
    }

    void AuthService::SetAuthenticator(Authenticator *authenticator)
    {
        _authenticator = authenticator;
    }

    void AuthService::Start(void)
    {
        if (!_running) {
            _running = true;
            if (_activeTasks.size() != 0)
                Next();
        }
    }

    void AuthService::Enqueue(Internal::AuthTask task)
    {
        _activeTasks.push_back(task);
        if (!_running)
            return;
        if (_activeTasks.size() == 1)
            Next();
    }
    
    void AuthService::Next(void)
    {
        if (_activeTasks.size() == 0)
            return;
        // Start up!
        Internal::AuthTask &task = _activeTasks.front();
        Authenticator::Replier replier(task);
        task.authenticator->Query(&replier, std::nullopt, false);

        DEBUG_LOG_STATE(("Requesting auth service: %s\n", task._name.c_str()));
    }

    void AuthService::HandlePayload(Types::Blob data)
    {
        Types::Reader reader(data);
        switch (reader.ReadByte()) {
            case USERAUTH_SUCCESS:
            {
                Internal::AuthTask &task = _activeTasks.front();
                task._service->Start();
                DEBUG_LOG_STATE(("Service accepted\n"));
                _activeTasks.erase(_activeTasks.begin());
                Next();
            }
                break;
            case USERAUTH_PASSWD_CHANGEREQ:
            {
                Types::Blob message = reader.ReadString();
                Types::Blob languageTag = reader.ReadString();
                Internal::AuthTask &task = _activeTasks.front();
                Authenticator::Replier replier(task);
                task.authenticator->NeedChangePassword(&replier, message.AsString(), languageTag.AsString());
            }
                break;
            case USERAUTH_FAILURE:
            {
                std::vector<std::string> acceptedModes = reader.ReadNameList();
                bool partialSuccess = reader.ReadBoolean();
                Internal::AuthTask &task = _activeTasks.front();
                Authenticator::Replier replier(task);
                task.authenticator->Query(&replier, acceptedModes, partialSuccess);
            }
                break;
            case USERAUTH_BANNER:
            {
                Types::Blob message = reader.ReadString();
                Types::Blob languageTag = reader.ReadString();
                Internal::AuthTask &task = _activeTasks.front();
                Authenticator::Replier replier(task);
                task.authenticator->Banner(&replier, message.AsString(), languageTag.AsString());
            }
                break;
        }
    }

    std::shared_ptr<Core::Client::Enabler> AuthService::AuthEnabler(void)
    {
        if (!_authenticator)
            throw new std::runtime_error("Authenticator not set");
        return std::make_shared<Enabler>(*this, _owner, _authenticator);
    }
}

} // namespace minissh
