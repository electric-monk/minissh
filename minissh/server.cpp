//
//  main.cpp
//  miniserver
//
//  Created by Colin David Munro on 3/08/2020.
//  Copyright © 2020 MICE Software. All rights reserved.
//

#include "Server.h"
#include "TestRandom.h"
#include "TestNetwork.h"
#include "TestUtils.h"
#include "DiffieHellman.h"
#include "SshAuth.h"

#include "RSA.h"
#include "Hash.h"

class Client : public minissh::Server::IAuthenticator
{
public:
    Client(minissh::Maths::IRandomSource& randomiser, std::shared_ptr<Socket> connection)
    :_network(connection)
    ,_server(randomiser)
    ,_auth(_server, _server.DefaultServiceHandler() ,*this)
    ,_connection(_server, _auth.AuthServiceHandler())
    {
        _network->transport = &_server;
        _server.SetDelegate(_network.get());
        ConfigureSSH(_server.configuration);
        _server.Start();
    }
    
    std::optional<std::string> Banner() override
    {
        return "Hello there! How are you today?";
    }
    
    std::optional<bool> ConfirmPassword(std::string requestedService, std::string username, std::string password) override
    {
        return true;
    }
    
    bool ConfirmPasswordWithNew(std::string requestedService, std::string username, std::string password, std::string newPassword) override
    {
        return false;
    }

private:
    std::shared_ptr<Socket> _network;
    minissh::Core::Server _server;
    minissh::Server::AuthService _auth;
    minissh::Core::Connection::Server _connection;
};

class Server : public Listener
{
public:
    Server(minissh::Maths::IRandomSource& randomiser, int port)
    :Listener(port), _randomiser(randomiser)
    {
        fprintf(stdout, "Generating host key...");
        fflush(stdout);
        _hostKey = std::make_shared<minissh::RSA::KeySet>(_randomiser, 1024);
        fprintf(stdout, "Done\n");
    }

    void OnAccepted(std::shared_ptr<Socket> connection) override
    {
        connection->hostKey = _hostKey;
        new Client(_randomiser, connection);
    }
private:
    minissh::Maths::IRandomSource &_randomiser;
    std::shared_ptr<minissh::RSA::KeySet> _hostKey;
};

int main(int argc, const char * argv[])
{
    TestRandom randomiser;
    Server test(randomiser, 12348);
    BaseFD::Run();
    
    return 0;
}
