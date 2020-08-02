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
    class IAuthenticator;
    
    namespace Internal {

        struct AuthTask
        {
            Core::Client *_client;
            std::string _name;
            Core::Client::IService *_service;
            IAuthenticator *authenticator;
        };

    }

    /**
     * Interface to provide the library an authentication mechanism.
     */
    class IAuthenticator
    {
    public:
        /**
         * Class to provide a means for the IAuthenticator implementation to respond.
         */
        class Replier
        {
        public:
            Replier(Internal::AuthTask& task);
            
            std::string Name(void);
            Core::Client::IService& Service(void);
            void SendPassword(const std::string& username, const std::string& password, const std::optional<std::string>& newPassword = std::nullopt);
            // TODO: public key
            
        private:
            Internal::AuthTask &_task;
        };
        
        virtual void Banner(Replier *replier, const std::string& message, const std::string& languageTag) = 0;
        virtual void Query(Replier *replier, const std::optional<std::vector<std::string>>& acceptedModes, bool partiallyAccepted) = 0;
        virtual void NeedChangePassword(Replier *replier, const std::string& prompt, const std::string& languageTag) = 0;
    };
    
    /**
     * Implementation of the "ssh-auth" service.
     */
    class AuthService : public Core::Client::IService
    {
    public:
        AuthService(Core::Client& owner, std::shared_ptr<Core::Client::IEnabler> enabler);
        ~AuthService();

        void Start(void);
        
        void HandlePayload(Types::Blob data);
        
        void SetAuthenticator(IAuthenticator* authenticator);
        
        std::shared_ptr<Core::Client::IEnabler> AuthEnabler(void);
        
        void Enqueue(Internal::AuthTask task);

    private:
        bool _running;
        Core::Client &_owner;
        IAuthenticator *_authenticator;
        std::vector<Internal::AuthTask> _activeTasks;
        
        void Next(void);
    };
}

} // namespace minissh
