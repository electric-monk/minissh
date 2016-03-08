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

//#define TEST        argv[1]
#define TEST        "10.116.205.5"

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

static LargeNumber* MakeBig(LargeNumber *other)
{
    LargeNumber *temp = new LargeNumber(1024);
    for (int i = 0; i < 8; i++)
        other = other->Multiply(temp);
    temp->Release();
    return other;
}
//
//static LargeNumber* MakeSmall(LargeNumber *other)
//{
//    LargeNumber *temp = new LargeNumber(1024);
//    for (int i = 0; i < 10; i++)
//        other = other->Divide(temp, NULL);
//    temp->Release();
//    return other;
//}
//
//static int max(int a, int b) { if (a>b) return a; else return b; }
//
//const UInt32 diffieHellman_group1[] = {
//    0xFFFFFFFF, 0xFFFFFFFF, 0xC90FDAA2, 0x2168C234, 0xC4C6628B, 0x80DC1CD1,
//    0x29024E08, 0x8A67CC74, 0x020BBEA6, 0x3B139B22, 0x514A0879, 0x8E3404DD,
//    0xEF9519B3, 0xCD3A431B, 0x302B0A6D, 0xF25F1437, 0x4FE1356D, 0x6D51C245,
//    0xE485B576, 0x625E7EC6, 0xF44C42E9, 0xA637ED6B, 0x0BFF5CB6, 0xF406B7ED,
//    0xEE386BFB, 0x5A899FA5, 0xAE9F2411, 0x7C4B1FE6, 0x49286651, 0xECE65381,
//    0xFFFFFFFF, 0xFFFFFFFF
//};
//
//LargeNumber* Prime(void)
//{
//    LargeNumber *result = new LargeNumber(diffieHellman_group1, sizeof(diffieHellman_group1) / sizeof(diffieHellman_group1[0]), true);
//    result->Autorelease();
//    return result;
//}
//

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
        sshString *username = new sshString();
        username->AppendFormat("<username>");
        sshString *password = new sshString();
        password->AppendFormat("<password>");
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
    
//    LargeNumber *tenticle = Prime();
//    tenticle->Print(stdout);
//    printf("%s\n", tenticle->IsProbablePrime(100)?"prime":"not prime");
//    LargeNumber *one = new LargeNumber(23);
//    LargeNumber *two = new LargeNumber(10);
//    
//    one = MakeBig(one);
//    two = MakeBig(two);
//
//    LargeNumber *remainder;
//    LargeNumber *resultz = one->Divide(two, &remainder);
//    printf("one: "); one->Print(stdout);
//    printf("two: "); two->Print(stdout);
//    printf("result: "); resultz->Print(stdout);
//    printf("remains: "); remainder->Print(stdout);
//    remainder = MakeSmall(remainder);
//    printf("remains small: "); remainder->Print(stdout);
//    
//    const unsigned char bob[]={0xed, 0xcc};
//    LargeNumber *bobby = new LargeNumber(bob, sizeof(bob));
//    printf("bob: "); bobby->Print(stdout);
//    
//    const unsigned char jim[]={0xff,0x21,0x52,0x41,0x11};
//    LargeNumber *jimmy = new LargeNumber(jim, sizeof(jim));
//    printf("jim: "); jimmy->Print(stdout);
//    
//    const unsigned char frank[]={0x09,0xa3,0x78,0xf9,0xb2,0xe3,0x32,0xa7};
//    LargeNumber *frankie = new LargeNumber(frank, sizeof(frank));
//    printf("frank: "); frankie->Print(stdout);
//    
//    const unsigned char testdata[]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
//    LargeNumber *test = new LargeNumber(testdata, sizeof(testdata));
//    while (!test->IsZero()) {
//        test->Print(stdout);
//        test = test->ShiftRight(1);
//    }
    LargeNumber *test1 = new LargeNumber(1);
    LargeNumber *test2 = MakeBig(new LargeNumber(2));
    LargeNumber *testResult = test1->Subtract(test2);
    fprintf(stdout, "One: "); test1->Print(stdout);
    fprintf(stdout, "Two: "); test2->Print(stdout);
    fprintf(stdout, "1-2: "); testResult->Print(stdout);
//    LargeNumber *taunt0 = one;
//    LargeNumber *taunt1 = two;
////    LargeNumber *taunt0 = new LargeNumber(2);
////    LargeNumber *taunt1 = new LargeNumber(12);
//    LargeNumber *taunt2 = new LargeNumber(1000);
//    LargeNumber *taunt = taunt0->PowerMod(taunt1, taunt2);
//    fprintf(stdout, "Base: "); taunt0->Print(stdout);
//    fprintf(stdout, "Power: "); taunt1->Print(stdout);
//    fprintf(stdout, "Divide: "); taunt2->Print(stdout);
//    fprintf(stdout, "Result: "); taunt->Print(stdout);
    
//    static UInt32 tests[] = {
//        1, 1, 3,             2,             1,      1,
//        1, 1, 3,             3,             1,      0,
//        1, 1, 3,             4,             0,      3,
//        1, 1, 0,             0xffffffff,    0,      0,
//        1, 1, 0xffffffff,    1,             0xffffffff, 0,
//        1, 1, 0xffffffff,    0xffffffff,    1,      0,
//        1, 1, 0xffffffff,    3,             0x55555555, 0,
//        2, 1, 0xffffffff,0xffffffff, 1,     0xffffffff,0xffffffff, 0,
//        2, 1, 0xffffffff,0xffffffff, 0xffffffff,        1,1,    0,
//        2, 1, 0xffffffff,0xfffffffe, 0xffffffff,        0xffffffff,0, 0xfffffffe,
//        2, 1, 0x00005678,0x00001234, 0x00009abc,        0x1e1dba76,0, 0x6bd0,
//        2, 2, 0,0,           0,1,           0,      0,0,
//        2, 2, 0,7,           0,3,           2,      0,1,
//        2, 2, 5,7,           0,3,           2,      5,1,
//        2, 2, 0,6,           0,2,           3,      0,0,
//        1, 1, 0x80000000,  0x40000001, 0x00000001, 0x3fffffff,
//        2, 1, 0x00000000,0x80000000, 0x40000001, 0xfffffff8,0x00000001, 0x00000008,
//        2, 2, 0x00000000,0x80000000, 0x00000001,0x40000000, 0x00000001, 0xffffffff,0x3fffffff,
//        2, 2, 0x0000789a,0x0000bcde, 0x0000789a,0x0000bcde,          1,          0,0,
//        2, 2, 0x0000789b,0x0000bcde, 0x0000789a,0x0000bcde,          1,          1,0,
//        2, 2, 0x00007899,0x0000bcde, 0x0000789a,0x0000bcde,          0, 0x00007899,0x0000bcde,
//        2, 2, 0x0000ffff,0x0000ffff, 0x0000ffff,0x0000ffff,          1,          0,0,
//        2, 2, 0x0000ffff,0x0000ffff, 0x00000000,0x00000001, 0x0000ffff, 0x0000ffff,0,
//        3, 2, 0x000089ab,0x00004567,0x00000123, 0x00000000,0x00000001,   0x00004567,0x00000123, 0x000089ab,0,
//        3, 2, 0x00000000,0x0000fffe,0x00008000, 0x0000ffff,0x00008000,   0xffffffff,0x00000000, 0x0000ffff,0x00007fff, // Shows that first qhat can = b + 1.
//        3, 3, 0x00000003,0x00000000,0x80000000, 0x00000001,0x00000000,0x20000000,   0x00000003, 0,0,0x20000000, // Adding back step req'd.
//        3, 3, 0x00000003,0x00000000,0x00008000, 0x00000001,0x00000000,0x00002000,   0x00000003, 0,0,0x00002000, // Adding back step req'd.
//        4, 3, 0,0,0x00008000,0x00007fff, 1,0,0x00008000,   0xfffe0000,0, 0x00020000,0xffffffff,0x00007fff,  // Add back req'd.
//        4, 3, 0,0x0000fffe,0,0x00008000, 0x0000ffff,0,0x00008000, 0xffffffff,0, 0x0000ffff,0xffffffff,0x00007fff,  // Shows that mult-sub quantity cannot be treated as signed.
//        4, 3, 0,0xfffffffe,0,0x80000000, 0x0000ffff,0,0x80000000, 0x00000000,1, 0x00000000,0xfffeffff,0x00000000,  // Shows that mult-sub quantity cannot be treated as signed.
//        4, 3, 0,0xfffffffe,0,0x80000000, 0xffffffff,0,0x80000000, 0xffffffff,0, 0xffffffff,0xffffffff,0x7fffffff,  // Shows that mult-sub quantity cannot be treated as signed.
//    };
//    
//    int i = 0, count = 0, failed = 0;
//    while (i < sizeof(tests)/4) {
//        count++;
//        int m = tests[i];
//        int n = tests[i + 1];
//        LargeNumber *top = new LargeNumber((UInt32*)(tests + i + 2), m);
//        LargeNumber *bottom = new LargeNumber((UInt32*)(tests + i + 2 + m), n);
//        LargeNumber *result = new LargeNumber((UInt32*)(tests + i + 2 + m + n), max(m-n+1, 1));
//        LargeNumber *remainder = new LargeNumber((UInt32*)(tests + i + 2 + m + n + max(m-n+1, 1)), n);
//        LargeNumber *gotRem;
//        LargeNumber *got = top->Divide(bottom, &gotRem);
//        bool good = true;
//        if (!got->IsEqual(result)) {
//            printf("Test %i failed result\n", count);
//            good = false;
//        }
//        if (!gotRem->IsEqual(remainder)) {
//            printf("Test %i failed remainder\n", count);
//            good = false;
//        }
//        if (!good) {
//            failed++;
//            printf("Test %i\n", count);
//            printf("Divide "); top->Print(stdout);
//            printf("By "); bottom->Print(stdout);
//            printf("Result "); got->Print(stdout);
//            printf("Expected "); result->Print(stdout);
//            printf("Remainder "); gotRem->Print(stdout);
//            printf("Expected "); remainder->Print(stdout);
//        }
//        i = i + 2 + m + n + max(m-n+1, 1) + n;
//    }
//    printf("Failed %i of %i tests\n", failed, count);
//    
//    LargeNumber *testPrime = new LargeNumber(10177);
//    printf("Test prime: "); testPrime->Print(stdout);
//    printf("Is: %s\n", testPrime->IsProbablePrime(100) ? "prime" : "not prime");
//
//    const char *testPrimeString = "155251809230070893513091813125848175563133404943451431320235"
//                                  "119490296623994910210725866945387659164244291000768028886422"
//                                  "915080371891804634263272761303128298374438082089019628850917"
//                                  "0691316593175367469551763119843371637221007210577919";
//    const char *testPrimeString = "179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194";
//    const UInt32 diffieHellman_group14[] = {
//        0xFFFFFFFF, 0xFFFFFFFF, 0xC90FDAA2, 0x2168C234, 0xC4C6628B, 0x80DC1CD1,
//        0x29024E08, 0x8A67CC74, 0x020BBEA6, 0x3B139B22, 0x514A0879, 0x8E3404DD,
//        0xEF9519B3, 0xCD3A431B, 0x302B0A6D, 0xF25F1437, 0x4FE1356D, 0x6D51C245,
//        0xE485B576, 0x625E7EC6, 0xF44C42E9, 0xA637ED6B, 0x0BFF5CB6, 0xF406B7ED,
//        0xEE386BFB, 0x5A899FA5, 0xAE9F2411, 0x7C4B1FE6, 0x49286651, 0xECE45B3D,
//        0xC2007CB8, 0xA163BF05, 0x98DA4836, 0x1C55D39A, 0x69163FA8, 0xFD24CF5F,
//        0x83655D23, 0xDCA3AD96, 0x1C62F356, 0x208552BB, 0x9ED52907, 0x7096966D,
//        0x670C354E, 0x4ABC9804, 0xF1746C08, 0xCA18217C, 0x32905E46, 0x2E36CE3B,
//        0xE39E772C, 0x180E8603, 0x9B2783A2, 0xEC07A28F, 0xB5C55DF0, 0x6F4C52C9,
//        0xDE2BCBF6, 0x95581718, 0x3995497C, 0xEA956AE5, 0x15D22618, 0x98FA0510,
//        0x15728E5A, 0x8AACAA68, 0xFFFFFFFF, 0xFFFFFFFF
//    };
//    
//    LargeNumber *preTaunt = new LargeNumber(diffieHellman_group14, sizeof(diffieHellman_group14) / sizeof(diffieHellman_group14[0]), true);
//    printf("Preprime "); preTaunt->Print(stdout);
//    printf("Is: %s\n", preTaunt->IsProbablePrime(100) ? "prime" : "not prime");
//    preTaunt->Release();
//
//    LargeNumber *testing = new LargeNumber(0);
//    LargeNumber *ten = new LargeNumber(10);
//    for (const char *c = testPrimeString; *c; c++) {
//        testing = testing->Multiply(ten);
//        LargeNumber *charNum = new LargeNumber(*c - '0');
//        testing = testing->Add(charNum);
//        charNum->Release();
//    }
//    ten->Release();
//    printf("Oakley known giant prime ");
//    testing->Print(stdout);
//    printf("Is: %s\n", testing->IsProbablePrime(100) ? "prime" : "not prime");
//
//    TestRandom testRandom;
//    BlumBlumShub *blum = new BlumBlumShub(512, &testRandom);
//    blum->SetSeed((Byte*)frank, sizeof(frank));
//    
//    printf("Randoming: ");
//    for (int i = 0; i < 10; i++) {
//        printf(" %i", blum->Random());
//    }
//    printf("\n");

//    const Byte data[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
//    sshBlob *testAESKey = new sshBlob();
//    testAESKey->Append(data, sizeof(data));
//    AES *testAES = new AES(testAESKey);
//    testAESKey->Release();
//    const Byte testKey[] =          {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
//    const Byte testPlaintext[] =    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
//    sshBlob *plainTextBlob = new sshBlob();
//    plainTextBlob->Append(testPlaintext, sizeof(testPlaintext));
//    sshBlob *keyBlob = new sshBlob();
//    keyBlob->Append(testKey, sizeof(testKey));
//    AES *testAES = new AES(keyBlob);
//    sshBlob *result = testAES->Encrypt(plainTextBlob);
//    
//    sshBlob *decoded = testAES->Decrypt(result);
    
    SocketTest *test = new SocketTest("10.116.205.5", /*22*/10001);
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
    TestAuthentication *testAuth = new TestAuthentication();
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
