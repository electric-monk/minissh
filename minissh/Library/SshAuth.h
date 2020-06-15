//
//  SshAuth.h
//  minissh
//
//  Created by Colin David Munro on 16/02/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#pragma once

#include <stdlib.h>
#include "Client.h"

namespace minissh {

// Server

// Client

namespace Client {
    class Authenticator;
    
    namespace Internal {

        struct AuthTask
        {
            Core::Client *_client;
            std::string _name;
            Core::Client::Service *_service;
            Authenticator *authenticator;
        };

    }

    class Authenticator
    {
    public:
        class Replier
        {
        public:
            Replier(Internal::AuthTask& task);
            
            std::string Name(void);
            Core::Client::Service& Service(void);
            void SendPassword(const std::string& username, const std::string& password, const std::optional<std::string>& newPassword = std::nullopt);
            // TODO: public key
            
        private:
            Internal::AuthTask &_task;
        };
        
        virtual void Banner(Replier *replier, const std::string& message, const std::string& languageTag) = 0;
        virtual void Query(Replier *replier, const std::optional<std::vector<std::string>>& acceptedModes, bool partiallyAccepted) = 0;
        virtual void NeedChangePassword(Replier *replier, const std::string& prompt, const std::string& languageTag) = 0;
    };
    
    class AuthService : public Core::Client::Service
    {
    public:
        AuthService(Core::Client& owner, std::shared_ptr<Core::Client::Enabler> enabler);
        ~AuthService();

        void Start(void);
        
        void HandlePayload(Types::Blob data);
        
        void SetAuthenticator(Authenticator* authenticator);
        
        std::shared_ptr<Core::Client::Enabler> AuthEnabler(void);
        
        void Enqueue(Internal::AuthTask task);

    private:
        bool _running;
        Core::Client &_owner;
        Authenticator *_authenticator;
        std::vector<Internal::AuthTask> _activeTasks;
        
        void Next(void);
    };
}

} // namespace minissh
