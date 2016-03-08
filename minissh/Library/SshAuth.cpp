//
//  SshAuth.cpp
//  minissh
//
//  Created by Colin David Munro on 16/02/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#include "SshAuth.h"
#include "SshNumbers.h"
#include <stdio.h>
#include <memory.h>

namespace SshClient {
    const Byte messages[] = {SSH_MSG_USERAUTH_BANNER, SSH_MSG_USERAUTH_FAILURE, SSH_MSG_USERAUTH_SUCCESS};

    class AuthTask : public sshObject
    {
    public:
        AuthTask(sshClient *client, const char *serviceName, sshClient::Service *service, Authenticator *auth)
        {
            this->client = client;
            name = new sshString();
            name->AppendFormat("%s", serviceName);
            this->service = service;
            this->service->AddRef();
            authenticator = auth;
            authenticator->AddRef();
        }
        
        ~AuthTask()
        {
            service->Release();
            name->Release();
            authenticator->Release();
        }
        
        sshString *name;
        sshClient *client;
        sshClient::Service *service;
        Authenticator *authenticator;
    };
    
    namespace Internal {
        class Enabler : public sshClient::Enabler
        {
        public:
            Enabler(Auth *owner, sshDictionary *dictionary, sshClient *client, Authenticator *auth)
            {
                _owner = owner;
                _dictionary = dictionary;
                _client = client;
                _auth = auth;
            }
            
            void Request(const char *name, sshClient::Service *service)
            {
                AuthTask *task = new AuthTask(_client, name, service, _auth);
                _dictionary->Set(task->name, task);
                task->Release();
                _owner->Check();
            }
            
            void HandlePayload(sshBlob *data)
            {
                // We don't use this as a message handler
            }
            
        private:
            Auth *_owner;
            sshDictionary *_dictionary;
            sshClient *_client;
            Authenticator *_auth;
        };
    }

    Authenticator::Replier::Replier(AuthTask *task)
    {
        _task = task;
    }
    
    sshString* Authenticator::Replier::Name(void)
    {
        return _task->name;
    }
    
    sshClient::Service* Authenticator::Replier::Service(void)
    {
        return _task->service;
    }
    
    void Authenticator::Replier::SendPassword(sshString *username, sshString *password, sshString *newPassword)
    {
        sshBlob *message = new sshBlob();
        sshWriter writer(message);
        writer.Write(Byte(SSH_MSG_USERAUTH_REQUEST));
        writer.Write(username);
        writer.Write(Name());
        sshString *pwd = new sshString();
        pwd->AppendFormat("password");
        writer.Write(pwd);
        pwd->Release();
        bool hasNewPassword = newPassword != NULL;
        writer.Write(bool(hasNewPassword));
        writer.Write(password);
        if (hasNewPassword)
            writer.Write(newPassword);
        _task->client->Send(message);
        message->Release();
    }
    
    Auth::Auth(sshClient *owner, sshClient::Enabler *enabler)
    {
        _running = false;
        _dictionary = new sshDictionary();
        enabler->Request("ssh-userauth", this);
        _owner = owner;
        _owner->RegisterForPackets(this, messages, sizeof(messages) / sizeof(messages[0]));
        _authenticator = NULL;
    }
    
    Auth::~Auth()
    {
        if (_authenticator)
            _authenticator->Release();
        _owner->UnregisterForPackets(messages, sizeof(messages) / sizeof(messages[0]));
        _dictionary->Release();
    }

    void Auth::SetAuthenticator(Authenticator *authenticator)
    {
        if (_authenticator)
            _authenticator->Release();
        _authenticator = authenticator;
        if (_authenticator)
            _authenticator->AddRef();
    }

    void Auth::Start(void)
    {
        if (!_running) {
            _running = true;
            if (_dictionary->AllKeys()->Count() != 0)
                Next();
        }
    }

    void Auth::Check(void)
    {
        if (!_running)
            return;
        if (_dictionary->AllKeys()->Count() == 1)
            Next();
    }
    
    static AuthTask* CurrentTask(sshDictionary *dictionary)
    {
        sshString *name = dictionary->AllKeys()->ItemAt(0);
        return (AuthTask*)dictionary->ObjectFor(name);
    }
    
    static void RemoveCurrentTask(sshDictionary *dictionary)
    {
        sshString *name = dictionary->AllKeys()->ItemAt(0);
        dictionary->Set(name, NULL);
    }
    
    void Auth::Next(void)
    {
        if (_dictionary->AllKeys()->Count() == 0)
            return;
        // Start up!
        AuthTask *task = CurrentTask(_dictionary);
        Authenticator::Replier replier(task);
        task->authenticator->Query(&replier, NULL, false);

        char *temp = new char[_dictionary->AllKeys()->ItemAt(0)->Length() + 1];
        memcpy(temp, _dictionary->AllKeys()->ItemAt(0)->Value(), _dictionary->AllKeys()->ItemAt(0)->Length());
        temp[_dictionary->AllKeys()->ItemAt(0)->Length()] = 0;
        DEBUG_LOG_STATE(("Requesting auth service: %s\n", temp));
        delete[] temp;
    }

    void Auth::HandlePayload(sshBlob *data)
    {
        sshReader reader(data);
        switch (reader.ReadByte()) {
            case SSH_MSG_USERAUTH_SUCCESS:
            {
                AuthTask *task = CurrentTask(_dictionary);
                task->service->Start();
                DEBUG_LOG_STATE(("Service accepted\n"));
                RemoveCurrentTask(_dictionary);
                Next();
            }
                break;
            case SSH_MSG_USERAUTH_PASSWD_CHANGEREQ:
            {
                sshString *message = reader.ReadString();
                sshString *languageTag = reader.ReadString();
                AuthTask *task = CurrentTask(_dictionary);
                Authenticator::Replier replier(task);
                task->authenticator->NeedChangePassword(&replier, message, languageTag);
            }
                break;
            case SSH_MSG_USERAUTH_FAILURE:
            {
                sshNameList *acceptedModes = reader.ReadNameList();
                bool partialSuccess = reader.ReadBoolean();
                AuthTask *task = CurrentTask(_dictionary);
                Authenticator::Replier replier(task);
                task->authenticator->Query(&replier, acceptedModes, partialSuccess);
            }
                break;
            case SSH_MSG_USERAUTH_BANNER:
            {
                sshString *message = reader.ReadString();
                sshString *languageTag = reader.ReadString();
                AuthTask *task = CurrentTask(_dictionary);
                Authenticator::Replier replier(task);
                task->authenticator->Banner(&replier, message, languageTag);
            }
                break;
        }
    }

    sshClient::Enabler* Auth::AuthEnabler(void)
    {
        Internal::Enabler *result = new Internal::Enabler(this, _dictionary, _owner, _authenticator);
        result->Autorelease();
        return result;
    }
}
