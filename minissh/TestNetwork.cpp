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
#include "RSA.h"

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

BaseFD *start = nullptr, *end = nullptr;
    
} // namespace

BaseFD::BaseFD()
{
    _next = nullptr;
    _last = end;
    if (_last)
        _last->_next = this;
    else
        start = this;
    end = this;
}

BaseFD::~BaseFD()
{
    if (_last)
        _last->_next = _next;
    if (_next)
        _next->_last = _last;
    if (this == start)
        start = _next;
    if (this == end)
        end = _last;
}

BaseSocket::~BaseSocket()
{
    shutdown(_fd, SHUT_RDWR);
    close(_fd);
}

void BaseFD::Run(void)
{
    while (true) {
        fd_set set;
        int max = -1;
        FD_ZERO(&set);
        for (BaseFD *item = start; item; item = item->_next) {
            max = std::max(item->_fd, max);
            FD_SET(item->_fd, &set);
        }
        select(max + 1, &set, NULL, NULL, NULL);
        for (BaseFD *item = start; item; item = item->_next)
            if (FD_ISSET(item->_fd, &set))
                item->OnEvent();
    }
}

Socket::Socket(const char *host, unsigned short port)
{
    _fd = socket(PF_INET, SOCK_STREAM, 0);
    struct sockaddr_in isa = getipa(host, port);
    if (connect(_fd, (struct sockaddr*)&isa, sizeof isa) == -1) {
        fprintf(stderr, "Failed to connect\n");
        exit(-2);
    }
}

Socket::Socket(int fd)
{
    _fd = fd;
}

void Socket::OnEvent(void)
{
    char buf[1024];
    int res = (int)recv(_fd, buf, sizeof(buf), 0);
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

void Socket::Send(const void *data, minissh::UInt32 length)
{
    send(_fd, data, length, 0);
}

void Socket::Failed(minissh::Core::Client::PanicReason reason)
{
    fprintf(stderr, "Failure [%i]: %s\n", reason, minissh::Core::Client::StringForPanicReason(reason).c_str());
    exit(-1);
}

std::shared_ptr<minissh::Files::Format::IKeyFile> Socket::GetHostKey(void)
{
    return hostKey;
}

Listener::Listener(unsigned short port)
{
    _fd = socket(PF_INET, SOCK_STREAM, 0);
    struct sockaddr_in isa = getipa("0.0.0.0", port);
    if (bind(_fd, (struct sockaddr*)&isa, sizeof isa) < 0) {
        fprintf(stderr, "Error binding\n");
        exit(-10);
    }
    listen(_fd, 5);
}

void Listener::OnEvent(void)
{
    struct sockaddr_in isa;
    socklen_t isa_size = sizeof isa;
    int fd = accept(_fd, (struct sockaddr *)&isa, &isa_size);
    if (fd < 0) {
        fprintf(stderr, "Error on accept\n");
        exit(-11);
    }
    printf("Accepted connection from %s:%i\n", inet_ntoa(isa.sin_addr), ntohs(isa.sin_port));
    OnAccepted(std::make_shared<Socket>(fd));
}
