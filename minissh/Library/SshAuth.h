//
//  SshAuth.h
//  minissh
//
//  Created by Colin David Munro on 16/02/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#pragma once

#include <stdlib.h>
#include "Server.h"
#include "Client.h"

namespace minissh {

// Server

namespace Server {
    /**
     * Interface for providing authentication for clients.
     */
    class IAuthenticator
    {
    public:
        struct PublicKeyData {
            std::shared_ptr<Transport::IHostKeyAlgorithm> algorithm;
            std::shared_ptr<Files::Format::IKeyFile> keyFile;
        };
        
        virtual ~IAuthenticator() = default;
        
        /**
         * Optionally send a banner when authentication is requested.
         */
        virtual std::optional<std::string> Banner() { return {}; };
        
        /**
         * Validate a plaintext password.
         *
         * Return type is optional - if password is correct but you want it to change, return nothing to indicate
         * you want it changed.
         */
        virtual std::optional<bool> ConfirmPassword(std::string requestedService, std::string username, std::string password) = 0;
        
        /**
         * Get a password prompt.
         */
        virtual std::string PasswordPrompt(void) { return "Please change your password!"; }
        
        /**
         * Validate a plaintext password, and set a new password.
         */
        virtual bool ConfirmPasswordWithNew(std::string requestedService, std::string username, std::string password, std::string newPassword) = 0;

        /**
         * Confirm if a public key is known to the server.
         */
        virtual bool ConfirmKnownPublicKey(std::string requestedService, std::string username, std::string keyAlgorithm, Types::Blob publicKey) = 0;
        
        /**
         * Get signature algorithm, if the public key was known.
         */
        virtual PublicKeyData GetPublicKeyAlgorithm(std::string username, std::string keyAlgorithm, Types::Blob publicKey) = 0;
        
        // TODO: multiple authentications for a single session
    };
    
    /**
     * Implementation of the "ssh-auth" service.
     */
    class AuthService : public Core::Server::IServiceProvider
    {
    public:
        AuthService(Core::Server& owner, std::shared_ptr<Core::Server::IServiceHandler> enabler, IAuthenticator& authenticator);
        ~AuthService();
        
        void ServiceRequested(std::string name, std::optional<std::string> username) override;

        void HandlePayload(Types::Blob data) override;
        
        std::shared_ptr<Core::Server::IServiceHandler> AuthServiceHandler(void);

    private:
        Core::Server &_owner;
        IAuthenticator &_authenticator;
        bool _running;
        std::shared_ptr<Core::Server::IServiceHandler> _handler;
    };

}
    
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
        virtual ~IAuthenticator() = default;
        
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
