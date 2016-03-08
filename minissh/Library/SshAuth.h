//
//  SshAuth.h
//  minissh
//
//  Created by Colin David Munro on 16/02/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#ifndef __minissh__SshAuth__
#define __minissh__SshAuth__

#include <stdlib.h>
#include "Client.h"

// Server

// Client

namespace SshClient {
    class AuthTask;

    class Authenticator : public sshObject
    {
    public:
        class Replier
        {
        public:
            Replier(AuthTask *task);
            
            sshString* Name(void);
            sshClient::Service* Service(void);
            void SendPassword(sshString *username, sshString *password, sshString *newPassword = NULL);
            // TODO: public key
            
        private:
            AuthTask *_task;
        };
        
        virtual void Banner(Replier *replier, sshString *message, sshString *languageTag) = 0;
        virtual void Query(Replier *replier, sshNameList *acceptedModes, bool partiallyAccepted) = 0;
        virtual void NeedChangePassword(Replier *replier, sshString *prompt, sshString *languageTag) = 0;
    };
    
    class Auth : public sshClient::Service
    {
    public:
        Auth(sshClient *owner, sshClient::Enabler *enabler);
        
        void Start(void);
        
        void HandlePayload(sshBlob *data);
        
        void SetAuthenticator(Authenticator *authenticator);
        
        sshClient::Enabler* AuthEnabler(void);
        
        // Internal
        void Check(void);
        
    protected:
        ~Auth();
        
    private:
        bool _running;
        sshDictionary *_dictionary;
        sshClient *_owner;
        Authenticator *_authenticator;
        
        void Next(void);
    };
}

#endif /* defined(__minissh__SshAuth__) */
