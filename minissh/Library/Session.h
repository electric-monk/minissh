//
//  Session.h
//  minissh
//
//  Created by Colin David Munro on 20/02/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#pragma once

#include "Connection.h"

namespace minissh::Core {

/**
 * An SSH session, representing a single terminal.
 */
class Session : public Connection::Connection::AChannel
{
public:
    Session(Connection::Connection& owner);
    
    std::optional<Types::Blob> OpenInfo(std::string &nameOut, UInt32 &packetSize, UInt32 &windowSize) override;
    void Opened(Types::Blob data) override;
    void OpenFailed(UInt32 reason, const std::string& message, const std::string& languageTag) override;
    
    void ReceivedClose(void) override;
    void ReceivedData(Types::Blob data) override;
    void ReceivedExtendedData(UInt32 type, Types::Blob data) override;
    void ReceivedRequestResponse(bool success) override;
    
    void Send(const char *keystrokes, UInt32 length);
    
private:
    bool _shell;
};

/**
 * An SSH session provider, for testing the server.
 */
class SessionServer : public Connection::Connection::AChannel
{
public:
    SessionServer(Connection::Connection& owner):AChannel(owner){}

    class Provider : public Connection::Connection::IChannelProvider
    {
    public:
        std::shared_ptr<AChannel> AcceptChannel(Connection::Connection& owner, std::string channelType, Types::Blob extraData)
        {
            return std::make_shared<SessionServer>(owner);
        }
    };
protected:
    std::optional<Types::Blob> OpenInfo(std::string& nameOut, UInt32 &packetSize, UInt32 &windowSize) override {return {};}
    void Opened(Types::Blob data) override;
    
    void ReceivedClose(void) override;
    void ReceivedData(Types::Blob data) override;
    void ReceivedExtendedData(UInt32 type, Types::Blob data) override;
    bool ReceivedRequest(const std::string& request, std::optional<Types::Blob> data) override;
};
    
} // namespace minissh::Core
