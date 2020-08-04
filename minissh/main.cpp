//
//  main.cpp
//  minissh
//
//  Created by Colin David Munro on 10/01/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#include <stdio.h>          /* stderr, stdout */
#include <stdlib.h>
#include <unistd.h>
#include "Client.h"
#include "Connection.h"
#include "Session.h"

#include "SshAuth.h"

#include "TestRandom.h"
#include "TestUtils.h"
#include "TestNetwork.h"

class TestAuthentication : public minissh::Client::IAuthenticator
{
public:
    void Banner(Replier *replier, const std::string& message, const std::string& languageTag) override
    {
        printf("BANNER: %s\n", message.c_str());
    }
    
    void Query(Replier *replier, const std::optional<std::vector<std::string>>& acceptedModes, bool partiallyAccepted) override
    {
        // This is demo code - not thoroughly safe!
        char *username = NULL;
        size_t linecap = 0;
        printf("Username: ");
        ssize_t linelen = getline(&username, &linecap, stdin);
        username[linelen - 1] = '\0';    // Remove newline
        char *password = getpass("Password: ");
        replier->SendPassword(username, password);
    }
    
    void NeedChangePassword(Replier *replier, const std::string& prompt, const std::string& languageTag) override
    {
        printf("Server says we need to change password (%s)\n", prompt.c_str());
    }
};

int main(int argc, const char * argv[])
{
    if (argc < 2) {
        printf("usage: %s <host> [<port>]\n", argv[0]);
        return -1;
    }
    uint16_t portnum = 22;
    if (argc == 3)
        portnum = atoi(argv[2]);
    SocketTest *test = new SocketTest(argv[1], portnum);
    TestRandom randomiser;
    minissh::Core::Client client(randomiser);
    test->transport = &client;
    ConfigureSSH(test->transport->configuration);
    test->transport->SetDelegate(test);
    minissh::Client::AuthService *auth = new minissh::Client::AuthService(client, client.DefaultEnabler());
    TestAuthentication testAuth;
    auth->SetAuthenticator(&testAuth);
    minissh::Core::Connection connection(client, auth->AuthEnabler());
    std::shared_ptr<minissh::Core::Session> session = std::make_shared<minissh::Core::Session>(connection);
    connection.OpenChannel(session);
    test->session = session;
    test->transport->Start();
    test->Run();
    
    return 0;
}
