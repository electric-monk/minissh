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

#include "RSA.h"
#include "Hash.h"

class Client
{
public:
    Client(minissh::Maths::IRandomSource& randomiser, std::shared_ptr<Socket> connection)
    :_connection(connection), _server(randomiser)
    {
        _connection->transport = &_server;
        _server.SetDelegate(_connection.get());
        ConfigureSSH(_server.configuration);
        minissh::Types::Blob hostKey((minissh::Byte*)"Test", 4);
        _server.Start();
    }
    
private:
    std::shared_ptr<Socket> _connection;
    minissh::Core::Server _server;
};

class Server : public Listener
{
public:
    Server(minissh::Maths::IRandomSource& randomiser, int port)
    :Listener(port), _randomiser(randomiser)
    {
        _hostKey = std::make_shared<minissh::RSA::KeySet>(_randomiser, 1024);
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

minissh::Byte UnHex(char c)
{
    if ((c >= '0') && (c <= '9'))
        return c - '0';
    if ((c >= 'a') && (c <= 'f'))
        return c - 'a' + 10;
    if ((c >= 'A') && (c <= 'F'))
        return c - 'A' + 10;
    throw new std::runtime_error("Invalid character");
}

minissh::Maths::BigNumber LoadString(const char* data)
{
    int len = strlen(data) / 2;
    minissh::Byte *bobo = new minissh::Byte[len];
    for (int i = 0; i < len; i++)
        bobo[i] = (UnHex(data[(i * 2) + 0]) << 4) | UnHex(data[(i * 2) + 1]);
    minissh::Maths::BigNumber res(bobo, len);
    delete[] bobo;
    return res;
}

int main(int argc, const char * argv[])
{
    TestRandom randomiser;
    Server test(randomiser, 12348);
    BaseFD::Run();
    
    return 0;
}
