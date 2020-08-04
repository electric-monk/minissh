//
//  TestNetwork.cpp
//  minissh
//
//  Created by Colin David Munro on 3/08/2020.
//  Copyright © 2020 MICE Software. All rights reserved.
//

#include "TestNetwork.h"
#include <arpa/inet.h>      /* inet_ntoa() to format IP address */
#include <netinet/in.h>     /* in_addr structure */
#include <netdb.h>          /* hostent struct, gethostbyname() */
#include <stdio.h>          /* stderr, stdout */
#include <stdlib.h>
#include <memory.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>

namespace {
    
struct sockaddr_in getipa(const char* hostname, int port){
    struct sockaddr_in ipa;
    ipa.sin_family = AF_INET;
    ipa.sin_port = htons(port);
    
    struct hostent* localhost = gethostbyname(hostname);
    if (!localhost){
        fprintf(stderr, "Failed resolving host %s\n", hostname);
        exit(-1);
    }
    
    char* addr = localhost->h_addr_list[0];
    memcpy(&ipa.sin_addr.s_addr, addr, sizeof(ipa.sin_addr.s_addr));
    
    return ipa;
}

} // namespace

SocketTest::SocketTest(const char *host, unsigned short port)
{
    _sock = socket(PF_INET, SOCK_STREAM, 0);
    struct sockaddr_in isa = getipa(host, port);
    if (connect(_sock, (struct sockaddr*)&isa, sizeof isa) == -1) {
        fprintf(stderr, "Failed to connect\n");
        exit(-2);
    }
    session = NULL;
}

void SocketTest::Send(const void *data, minissh::UInt32 length)
{
    send(_sock, data, length, 0);
}

void SocketTest::Failed(minissh::Core::Client::PanicReason reason)
{
    fprintf(stderr, "Failure [%i]: %s\n", reason, minissh::Core::Client::StringForPanicReason(reason).c_str());
    exit(-1);
}

void SocketTest::Run(void)
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

SocketTest::~SocketTest()
{
    shutdown(_sock, SHUT_RDWR);
}
