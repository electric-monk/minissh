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

class Session : public minissh::Core::Connection::Connection::AChannel
{
public:
    Session(minissh::Core::Connection::Connection& owner)
    :minissh::Core::Connection::Connection::AChannel(owner)
    {
        _shell = false;
    }
    
    std::optional<minissh::Types::Blob> OpenInfo(std::string &nameOut, minissh::UInt32 &packetSize, minissh::UInt32 &windowSize) override
    {
        nameOut = "session";
        return {};
    }
    
    void Opened(minissh::Types::Blob data) override
    {
        minissh::Types::Blob parameters;
        minissh::Types::Writer writer(parameters);
        writer.WriteString("vt100");
        writer.Write(minissh::UInt32(80));
        writer.Write(minissh::UInt32(24));
        writer.Write(minissh::UInt32(640));
        writer.Write(minissh::UInt32(480));
        char terminalModes[] = {0};
        writer.WriteString(std::string(terminalModes, sizeof(terminalModes)));
        Request("pty-req", true, parameters);
    }
    
    void OpenFailed(minissh::UInt32 reason, const std::string& message, const std::string& languageTag) override
    {
        printf("Failed to create session: %i: %s\n", reason, message.c_str());
    }
    
    void ReceivedRequestResponse(bool success) override
    {
        if (!success) {
            printf("Failed to open TTY\n");
            return;
        }
        if (!_shell) {
            _shell = true;
            Request("shell", false, std::nullopt);
        }
    }
    
    void ReceivedClose(void) override
    {
        printf("Session closed\n");
    }
    
    void ReceivedData(minissh::Types::Blob data) override
    {
        for (int i = 0; i < data.Length(); i++)
            printf("%c", data.Value()[i]);
        fflush(stdout);
    }
    
    void ReceivedExtendedData(minissh::UInt32 type, minissh::Types::Blob data) override
    {
        for (int i = 0; i < data.Length(); i++)
            printf("%c", data.Value()[i]);
        fflush(stdout);
    }
    
    void Send(const char *keystrokes, minissh::UInt32 length)
    {
        AChannel::Send(minissh::Types::Blob((minissh::Byte*)keystrokes, length));
    }
    
private:
    bool _shell;
};

class Stdin : public BaseFD
{
public:
    Stdin(Session *session)
    :_session(session)
    {
        _fd = fileno(stdin);
    }
    
protected:
    void OnEvent(void) override
    {
        char c[100];
        int amount = (int)read(_fd, c, 100);
        _session->Send(c, amount);
    }
    
private:
    Session *_session;
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
    Socket *test = new Socket(argv[1], portnum);
    TestRandom randomiser;
    minissh::Core::Client client(randomiser);
    test->transport = &client;
    ConfigureSSH(test->transport->configuration);
    test->transport->SetDelegate(test);
    minissh::Client::AuthService *auth = new minissh::Client::AuthService(client, client.DefaultEnabler());
    TestAuthentication testAuth;
    auth->SetAuthenticator(&testAuth);
    minissh::Core::Connection::Client connection(client, auth->AuthEnabler());
    std::shared_ptr<Session> session = std::make_shared<Session>(connection);
    connection.OpenChannel(session);
    Stdin stdinRead(session.get());
    test->transport->Start();
    BaseFD::Run();
    return 0;
}
