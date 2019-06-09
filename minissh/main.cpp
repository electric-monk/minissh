//
//  main.cpp
//  minissh
//
//  Created by Colin David Munro on 10/01/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
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

class SocketTest : public sshTransport::Delegate
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
    
    void Send(const void *data, UInt32 length)
    {
        send(_sock, data, length, 0);
    }
    
    void Failed(sshTransport::PanicReason reason)
    {
        fprintf(stderr, "Failure: %i\n", reason);
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
    
    sshTransport *transport;
    sshSession *session;
    
protected:
    ~SocketTest()
    {
        shutdown(_sock, SHUT_RDWR);
    }

    int _sock;
};

class TestRandom : public RandomSource
{
public:
    UInt32 Random(void)
    {
        // WARNING: This is not secure, but just for testing.
        return rand();
    }
};

sshString* t(const char *s)
{
    sshString *r = new sshString();
    r->AppendFormat("%s", s);
    r->Autorelease();
    return r;
}

class TestAuthentication : public SshClient::Authenticator
{
public:
    void Banner(Replier *replier, sshString *message, sshString *languageTag)
    {
        char *temp = new char[message->Length() + 1];
        memcpy(temp, message->Value(), message->Length());
        temp[message->Length()] = 0;
        printf("BANNER: %s\n", temp);
        delete[] temp;
    }
    
    void Query(Replier *replier, sshNameList *acceptedModes, bool partiallyAccepted)
    {
        // This is demo code - not thoroughly safe!
        sshString *username = new sshString();
        char *rawuser = NULL;
        size_t linecap = 0;
        printf("Username: ");
        ssize_t linelen = getline(&rawuser, &linecap, stdin);
        rawuser[linelen - 1] = '\0';    // Remove newline
        username->AppendFormat(rawuser);
        sshString *password = new sshString();
        char *rawpass = getpass("Password: ");
        password->AppendFormat(rawpass);
        memset(rawpass, 0, password->Length());
        replier->SendPassword(username, password);
        username->Release();
        password->Release();
    }
    
    void NeedChangePassword(Replier *replier, sshString *prompt, sshString *languageTag)
    {
        printf("Server says we need to change password\n");
    }
};

int main(int argc, const char * argv[])
{
    sshObject::Releaser releaser;
    
    if (argc < 2) {
        printf("usage: %s <host> [<port>]\n", argv[0]);
        return -1;
    }
    uint16_t portnum = 22;
    TestAuthentication *testAuth;
    if (argc == 3)
        portnum = atoi(argv[2]);
    SocketTest *test = new SocketTest(argv[1], portnum);
    sshClient *client = new sshClient();
    test->transport = client;
    sshConfiguration::Factory::AddTo<dhGroup14::Factory>(test->transport->configuration->supportedKeyExchanges);
    sshConfiguration::Factory::AddTo<dhGroup1::Factory>(test->transport->configuration->supportedKeyExchanges);
    sshConfiguration::Factory::AddTo<SSH_RSA::Factory>(test->transport->configuration->serverHostKeyAlgorithms);
    sshConfiguration::Factory::AddTo<AES128_CBC::Factory>(test->transport->configuration->encryptionAlgorithms_clientToServer);
    sshConfiguration::Factory::AddTo<AES128_CBC::Factory>(test->transport->configuration->encryptionAlgorithms_serverToClient);
//    sshConfiguration::Factory::AddTo<AES192_CBC::Factory>(test->transport->configuration->encryptionAlgorithms_clientToServer);
//    sshConfiguration::Factory::AddTo<AES192_CBC::Factory>(test->transport->configuration->encryptionAlgorithms_serverToClient);
//    sshConfiguration::Factory::AddTo<AES256_CBC::Factory>(test->transport->configuration->encryptionAlgorithms_clientToServer);
//    sshConfiguration::Factory::AddTo<AES256_CBC::Factory>(test->transport->configuration->encryptionAlgorithms_serverToClient);
    sshConfiguration::Factory::AddTo<AES128_CTR::Factory>(test->transport->configuration->encryptionAlgorithms_clientToServer);
    sshConfiguration::Factory::AddTo<AES128_CTR::Factory>(test->transport->configuration->encryptionAlgorithms_serverToClient);
//    sshConfiguration::Factory::AddTo<AES192_CTR::Factory>(test->transport->configuration->encryptionAlgorithms_clientToServer);
//    sshConfiguration::Factory::AddTo<AES192_CTR::Factory>(test->transport->configuration->encryptionAlgorithms_serverToClient);
//    sshConfiguration::Factory::AddTo<AES256_CTR::Factory>(test->transport->configuration->encryptionAlgorithms_clientToServer);
//    sshConfiguration::Factory::AddTo<AES256_CTR::Factory>(test->transport->configuration->encryptionAlgorithms_serverToClient);
    sshConfiguration::Factory::AddTo<HMAC_SHA1::Factory>(test->transport->configuration->macAlgorithms_clientToServer);
    sshConfiguration::Factory::AddTo<HMAC_SHA1::Factory>(test->transport->configuration->macAlgorithms_serverToClient);
    sshObject *testtemp = new sshObject();
    test->transport->configuration->compressionAlgorithms_clientToServer->Set(t("none"), testtemp);
    test->transport->configuration->compressionAlgorithms_serverToClient->Set(t("none"), testtemp);
    test->transport->random = new TestRandom();
    test->transport->SetDelegate(test);
    SshClient::Auth *auth = new SshClient::Auth(client, client->DefaultEnabler());
    testAuth = new TestAuthentication();
    auth->SetAuthenticator(testAuth);
    testAuth->Release();
    sshConnection *connection = new sshConnection(client, auth->AuthEnabler());
    sshSession *session = new sshSession(connection);
    connection->OpenChannel(session);
    test->session = session;
    test->transport->Start();
    test->Run();
    
    return 0;
}
