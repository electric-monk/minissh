//
//  main.cpp
//  minissh
//
//  Created by Colin David Munro on 10/01/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#include <stdio.h>          /* stderr, stdout */
#include <netdb.h>          /* hostent struct, gethostbyname() */
#include <arpa/inet.h>      /* inet_ntoa() to format IP address */
#include <netinet/in.h>     /* in_addr structure */
#include <sys/socket.h>
#include <memory.h>
#include <stdlib.h>
#include <sys/select.h>
#include <unistd.h>
#include "Transport.h"
#include "Maths.h"
#include "BlumBlumShub.h"
#include "DiffieHellman.h"
#include "AES.h"
#include "Client.h"
#include "Connection.h"
#include "Session.h"

#include "SSH_RSA.h"
#include "SSH_AES.h"
#include "SSH_HMAC.h"
#include "SshAuth.h"

struct sockaddr_in getipa(const char* hostname, int port){
	struct sockaddr_in ipa;
	ipa.sin_family = AF_INET;
	ipa.sin_port = htons(port);
    
	struct hostent* localhost = gethostbyname(hostname);
	if(!localhost){
		fprintf(stderr, "failed resolveing localhost %s\n", hostname);
        exit(-1);
	}
    
	char* addr = localhost->h_addr_list[0];
	memcpy(&ipa.sin_addr.s_addr, addr, sizeof(ipa.sin_addr.s_addr));
    
	return ipa;
}

class SocketTest : public minissh::Core::Client::Delegate
{
public:
    SocketTest(const char *host, unsigned short port)
    {
        _sock = socket(PF_INET, SOCK_STREAM, 0);
        struct sockaddr_in isa = getipa(host, port);
        if (connect(_sock, (struct sockaddr*)&isa, sizeof isa) == -1) {
            fprintf(stderr, "Failed to connect\n");
            exit(-2);
        }
        session = NULL;
    }
    
    void Send(const void *data, minissh::UInt32 length)
    {
        send(_sock, data, length, 0);
    }
    
    void Failed(minissh::Core::Client::PanicReason reason)
    {
        fprintf(stderr, "Failure [%i]: %s\n", reason, minissh::Core::Client::StringForPanicReason(reason).c_str());
        exit(-1);
    }
    
    void Run(void)
    {
        char buf[1024];
        int fstdin = fileno(stdin);
        int max = ((fstdin > _sock) ? fstdin : _sock) + 1;
        while (true) {
            fd_set set;
            FD_ZERO(&set);
            FD_SET(_sock, &set);
            FD_SET(fstdin, &set);
            select(max, &set, NULL, NULL, NULL);
            if (FD_ISSET(fstdin, &set)) {
                char c[100];
                int amount = (int)read(fstdin, c, 100);
                session->Send(c, amount);
            }
            if (FD_ISSET(_sock, &set)) {
                int res = (int)recv(_sock, buf, sizeof(buf), 0);
                if (res == -1) {
                    fprintf(stderr, "Error reading\n");
                    exit(-3);
                }
                if (res == 0) {
                    fprintf(stderr, "Remote connection terminated\n");
                    exit(-4);
                }
                transport->Received(buf, res);
            }
        }
    }
    
    minissh::Transport::Transport *transport;
    std::shared_ptr<minissh::Core::Session> session;
    
protected:
    ~SocketTest()
    {
        shutdown(_sock, SHUT_RDWR);
    }

    int _sock;
};

class TestRandom : public minissh::Maths::RandomSource
{
public:
    TestRandom()
    {
        srand(time(NULL));
    }
    
    minissh::UInt32 Random(void) override
    {
        // WARNING: This is not secure, but just for testing.
        return rand();
    }
};

class TestAuthentication : public minissh::Client::Authenticator
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
    minissh::Algorithms::DiffieHellman::Group14::Factory::Add(test->transport->configuration.supportedKeyExchanges);
    minissh::Algorithms::DiffieHellman::Group1::Factory::Add(test->transport->configuration.supportedKeyExchanges);
    minissh::Algoriths::SSH_RSA::Factory::Add(test->transport->configuration.serverHostKeyAlgorithms);
    minissh::Algorithm::AES128_CBC::Factory::Add(test->transport->configuration.encryptionAlgorithms_clientToServer);
    minissh::Algorithm::AES128_CBC::Factory::Add(test->transport->configuration.encryptionAlgorithms_serverToClient);
    //minissh::Algorithm::AES192_CBC::Factory::Add(test->transport->configuration.encryptionAlgorithms_clientToServer);
    //minissh::Algorithm::AES192_CBC::Factory::Add(test->transport->configuration.encryptionAlgorithms_serverToClient);
    //minissh::Algorithm::AES256_CBC::Factory::Add(test->transport->configuration.encryptionAlgorithms_clientToServer);
    //minissh::Algorithm::AES256_CBC::Factory::Add(test->transport->configuration.encryptionAlgorithms_serverToClient);
    minissh::Algorithm::AES128_CTR::Factory::Add(test->transport->configuration.encryptionAlgorithms_clientToServer);
    minissh::Algorithm::AES128_CTR::Factory::Add(test->transport->configuration.encryptionAlgorithms_serverToClient);
    //minissh::Algorithm::AES192_CTR::Factory::Add(test->transport->configuration.encryptionAlgorithms_clientToServer);
    //minissh::Algorithm::AES192_CTR::Factory::Add(test->transport->configuration.encryptionAlgorithms_serverToClient);
    //minissh::Algorithm::AES256_CTR::Factory::Add(test->transport->configuration.encryptionAlgorithms_clientToServer);
    //minissh::Algorithm::AES256_CTR::Factory::Add(test->transport->configuration.encryptionAlgorithms_serverToClient);
    minissh::Algorithm::HMAC_SHA1::Factory::Add(test->transport->configuration.macAlgorithms_clientToServer);
    minissh::Algorithm::HMAC_SHA1::Factory::Add(test->transport->configuration.macAlgorithms_serverToClient);
    minissh::Transport::NoneCompression::Factory::Add(test->transport->configuration.compressionAlgorithms_clientToServer);
    minissh::Transport::NoneCompression::Factory::Add(test->transport->configuration.compressionAlgorithms_serverToClient);
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
