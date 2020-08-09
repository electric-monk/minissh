//
//  SshAuth.cpp
//  minissh
//
//  Created by Colin David Munro on 16/02/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#include "SshAuth.h"
#include "SshNumbers.h"
#include "KeyFile.h"
#include <stdio.h>
#include <memory.h>

namespace minissh {
    
namespace {
    constexpr const char* SERVICE_NAME = "ssh-userauth";
    constexpr const char* METHOD_KEY = "publickey";
    constexpr const char* METHOD_PASSWORD = "password";
}
    
namespace Server {
    const Byte messages[] = {USERAUTH_REQUEST};

    namespace {
        
        class AuthServiceList : public Core::Server::IServiceHandler
        {
        public:
            Core::Server &_owner;
            std::map<std::string, Core::Server::IServiceProvider*> _mapping;
        public:
            AuthServiceList(Core::Server& owner)
            :_owner(owner)
            {
            }
            
            void RegisterService(const std::string& name, Core::Server::IServiceProvider* provider) override
            {
                if (provider)
                    _mapping[name] = provider;
                else
                    _mapping.erase(name);
            }
            
            void HandlePayload(Types::Blob data) override
            {
                // Nothing to do, the auth service takes care of all packets
            }
            
            void LaunchService(std::string name, std::string username)
            {
                auto it = _mapping.find(name);
                if (it == _mapping.end()) {
                    DEBUG_LOG_STATE(("Auth service not registered!\n"));
                    _owner.Disconnect(DISCONNECT_SERVICE_NOT_AVAILABLE);
                } else {
                    it->second->ServiceRequested(name, username);
                }
            }
        };
        
    }
    
    AuthService::AuthService(Core::Server& owner, std::shared_ptr<Core::Server::IServiceHandler> enabler, IAuthenticator& authenticator)
    :_owner(owner), _authenticator(authenticator), _running(false), _handler(std::make_shared<AuthServiceList>(owner))
    {
        enabler->RegisterService(SERVICE_NAME, this);
    }

    AuthService::~AuthService()
    {
        if (_running)
            _owner.UnregisterForPackets(messages, sizeof(messages) / sizeof(messages[0]));
    }

    void AuthService::ServiceRequested(std::string name, std::optional<std::string> username)
    {
        if (_running)
            DEBUG_LOG_STATE(("%s requested twice?\n", SERVICE_NAME));
        // Initialise
        _running = true;
        _owner.RegisterForPackets(this, messages, sizeof(messages) / sizeof(messages[0]));
        // Send banner, if any
        std::optional<std::string> banner = _authenticator.Banner();
        if (banner) {
            Types::Blob data;
            Types::Writer writer(data);
            writer.Write(USERAUTH_BANNER);
            writer.WriteString(*banner);
            writer.WriteString(""); // language tag
            _owner.Send(data);
        }
    }

    void AuthService::HandlePayload(Types::Blob data)
    {
        Types::Reader reader(data);
        switch (reader.ReadByte()) {
            case USERAUTH_REQUEST:
            {
                Types::Blob response;
                Types::Writer writer(response);
                bool needResponse = true;
                bool valid = false;
                std::string userName = reader.ReadString().AsString();
                std::string serviceName = reader.ReadString().AsString();
                std::string methodName = reader.ReadString().AsString();
                DEBUG_LOG_STATE(("User authentication request for user '%s' with method '%s' for service '%s'\n", userName.c_str(), methodName.c_str(), serviceName.c_str()));
                if (methodName.compare(METHOD_PASSWORD) == 0) {
                    bool hasNewPassword = reader.ReadBoolean();
                    std::string password = reader.ReadString().AsString();
                    if (hasNewPassword) {
                        std::string newPassword = reader.ReadString().AsString();
                        valid = _authenticator.ConfirmPasswordWithNew(serviceName, userName, password, newPassword);
                    } else {
                        std::optional<bool> validOrChange = _authenticator.ConfirmPassword(serviceName, userName, password);
                        if (!validOrChange) {
                            // Send "requesting new password" packet
                            writer.Write(USERAUTH_PASSWD_CHANGEREQ);
                            writer.WriteString(_authenticator.PasswordPrompt());
                            writer.WriteString(""); // Language tag
                            needResponse = false;
                        } else {
                            valid = *validOrChange;
                        }
                    }
                } else if (methodName.compare(METHOD_KEY) == 0) {
                    bool hasSignature = reader.ReadBoolean();
                    std::string algorithm = reader.ReadString().AsString();
                    Types::Blob publicKey = reader.ReadString();
                    if (hasSignature) {
                        Types::Blob signature = reader.ReadString();
                        // Compute message
                        Types::Blob message;
                        Types::Writer writer(message);
                        writer.WriteString(*_owner.sessionID);
                        writer.Write(USERAUTH_REQUEST);
                        writer.WriteString(userName);
                        writer.WriteString(serviceName);
                        writer.WriteString(METHOD_KEY);
                        writer.Write((bool)true);
                        writer.WriteString(algorithm);
                        writer.WriteString(publicKey);
                        // Verify signature with message
                        IAuthenticator::PublicKeyData keyData = _authenticator.GetPublicKeyAlgorithm(userName, algorithm, publicKey);
                        valid = keyData.algorithm->Verify(*keyData.keyFile, signature, message);
                    } else {
                        if (_authenticator.ConfirmKnownPublicKey(serviceName, userName, algorithm, publicKey)) {
                            writer.Write(USERAUTH_PK_OK);
                            writer.WriteString(algorithm);
                            writer.WriteString(publicKey);
                            needResponse = false;
                        }
                    }
                }
                if (needResponse) {
                    if (valid) {
                        writer.Write(USERAUTH_SUCCESS);
                    } else {
                        std::vector<std::string> nameList;
                        nameList.push_back(METHOD_PASSWORD);
                        nameList.push_back(METHOD_KEY);
                        writer.Write(USERAUTH_FAILURE);
                        writer.Write(nameList);
                        writer.Write((bool)false);  // Partial success
                    }
                }
                _owner.Send(response);
                if (valid) {
                    DEBUG_LOG_STATE(("Launching authed service '%s' for user '%s'\n", serviceName.c_str(), userName.c_str()));
                    // Launch service
                    std::dynamic_pointer_cast<AuthServiceList>(_handler)->LaunchService(serviceName, userName);
                }
            }
                break;
            default:
                // We weren't subscribed to this?
                _owner.Panic(Core::Server::PanicReason::InvalidMessage);
                break;
        }
    }
    
    std::shared_ptr<Core::Server::IServiceHandler> AuthService::AuthServiceHandler(void)
    {
        return _handler;
    }

}

namespace Client {
    const Byte messages[] = {USERAUTH_BANNER, USERAUTH_FAILURE, USERAUTH_SUCCESS};

    namespace {
        class Enabler : public Core::Client::IEnabler
        {
        public:
            Enabler(AuthService& owner, Core::Client& client, IAuthenticator *auth)
            :_owner(owner), _client(client), _auth(auth)
            {
            }
            
            void Request(const std::string& name, Core::Client::IService* service) override
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
            IAuthenticator *_auth;
        };
    }

    IAuthenticator::Replier::Replier(const char **_replyMethod, Internal::AuthTask& task)
    :_method(_replyMethod), _task(task)
    {
    }
    
    std::string IAuthenticator::Replier::Name(void)
    {
        return _task._name;
    }
    
    Core::Client::IService& Client::IAuthenticator::Replier::Service(void)
    {
        return *_task._service;
    }
    
    void IAuthenticator::Replier::SendPassword(const std::string& username, const std::string& password, const std::optional<std::string>& newPassword)
    {
        *_method = METHOD_PASSWORD;
        Types::Blob message;
        Types::Writer writer(message);
        writer.Write(Byte(USERAUTH_REQUEST));
        writer.WriteString(username);
        writer.WriteString(Name());
        writer.WriteString(METHOD_PASSWORD);
        writer.Write(bool(newPassword));
        writer.WriteString(password);
        if (newPassword)
            writer.WriteString(*newPassword);
        _task._client->Send(message);
    }

    void IAuthenticator::Replier::DoPublicKey(const std::string& username, std::shared_ptr<Files::Format::IKeyFile> keySet, bool includeSignature)
    {
        *_method = METHOD_KEY;
        std::string keyAlgorithm = keySet->GetKeyName(Files::Format::FileType::SSH, false);
        Types::Blob message;
        Types::Writer writer(message);
        writer.Write(Byte(USERAUTH_REQUEST));
        writer.WriteString(username);
        writer.WriteString(Name());
        writer.WriteString(METHOD_KEY);
        writer.Write(bool(includeSignature));
        writer.WriteString(keyAlgorithm);
        writer.WriteString(Files::Format::SaveSSHKeys(keySet, false));
        if (includeSignature) {
            // Compute message
            Types::Blob sigMessage;
            Types::Writer sigWriter(sigMessage);
            sigWriter.WriteString(*_task._client->sessionID);
            sigWriter.Write(message);
            // Generate signature
            writer.WriteString(keySet->KeyAlgorithm()->Compute(*keySet, sigMessage));
        }
        _task._client->Send(message);
    }

    void IAuthenticator::Replier::SendPublicKey(const std::string& username, std::shared_ptr<Files::Format::IKeyFile> keySet)
    {
        DoPublicKey(username, keySet, false);
    }
    
    void IAuthenticator::Replier::UsePrivateKey(const std::string& username, std::shared_ptr<Files::Format::IKeyFile> keySet)
    {
        DoPublicKey(username, keySet, true);
    }

    AuthService::AuthService(Core::Client& owner, std::shared_ptr<Core::Client::IEnabler> enabler)
    :_running(false), _owner(owner), _authenticator(nullptr)
    {
        enabler->Request(SERVICE_NAME, this);
        _owner.RegisterForPackets(this, messages, sizeof(messages) / sizeof(messages[0]));
    }
    
    AuthService::~AuthService()
    {
        _owner.UnregisterForPackets(messages, sizeof(messages) / sizeof(messages[0]));
    }

    void AuthService::SetAuthenticator(IAuthenticator *authenticator)
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
        DEBUG_LOG_STATE(("Requesting auth service: %s\n", task._name.c_str()));
        IAuthenticator::Replier replier(&_lastRequest, task);
        task.authenticator->Query(replier, std::nullopt, false);
    }

    void AuthService::HandlePayload(Types::Blob data)
    {
        Types::Reader reader(data);
        switch (reader.ReadByte()) {
            case USERAUTH_SUCCESS:
            {
                _lastRequest = nullptr;
                Internal::AuthTask &task = _activeTasks.front();
                task._service->Start();
                DEBUG_LOG_STATE(("Auth service accepted [%s]\n", task._name.c_str()));
                _activeTasks.erase(_activeTasks.begin());
                Next();
            }
                break;
            case USERAUTH_MULTIMEANING_RESPONSE: // USERAUTH_PASSWD_CHANGEREQ or USERAUTH_PK_OK
            {
                const char *req = _lastRequest;
                _lastRequest = nullptr;
                Internal::AuthTask &task = _activeTasks.front();
                IAuthenticator::Replier replier(&_lastRequest, task);
                if (req == METHOD_PASSWORD) {
                    Types::Blob message = reader.ReadString();
                    Types::Blob languageTag = reader.ReadString();
                    task.authenticator->NeedChangePassword(replier, message.AsString(), languageTag.AsString());
                } else if (req == METHOD_KEY) {
                    std::string algorithmName = reader.ReadString().AsString();
                    Types::Blob publicKey = reader.ReadString();
                    task.authenticator->AcceptablePublicKey(replier, algorithmName, publicKey);
                } else {
                    // panic?
                }
            }
                break;
            case USERAUTH_FAILURE:
            {
                _lastRequest = nullptr;
                std::vector<std::string> acceptedModes = reader.ReadNameList();
                bool partialSuccess = reader.ReadBoolean();
                Internal::AuthTask &task = _activeTasks.front();
                IAuthenticator::Replier replier(&_lastRequest, task);
                task.authenticator->Query(replier, acceptedModes, partialSuccess);
            }
                break;
            case USERAUTH_BANNER:
            {
                Types::Blob message = reader.ReadString();
                Types::Blob languageTag = reader.ReadString();
                Internal::AuthTask &task = _activeTasks.front();
                IAuthenticator::Replier replier(&_lastRequest, task);
                task.authenticator->Banner(replier, message.AsString(), languageTag.AsString());
            }
                break;
        }
    }

    std::shared_ptr<Core::Client::IEnabler> AuthService::AuthEnabler(void)
    {
        if (!_authenticator)
            throw new std::runtime_error("Authenticator not set");
        return std::make_shared<Enabler>(*this, _owner, _authenticator);
    }
}

} // namespace minissh
