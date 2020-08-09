//
//  Connection.h
//  minissh
//
//  Created by Colin David Munro on 18/02/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#pragma once

#include "Transport.h"
#include "Client.h"
#include "Server.h"

namespace minissh::Core::Connection {

/**
 * Class implementing the "ssh-connection" service. Once established, this service works the same in both directions,
 * and so all the code is the same. Specific subclasses are provided to hook up the client (started by requesting it
 * of the server) and server (started when the client requests it).
 */
class Connection : public Transport::IMessageHandler
{
public:
    /**
     * Abstract base class implementing an individual channel within the service.
     */
    class AChannel
    {
    public:
        // Internal interface
        struct IPending {
            virtual ~IPending() = default;
            struct Root {
                IPending *start = nullptr;
                IPending *end = nullptr;
            };
        };
        
        AChannel(Connection& owner);
        virtual ~AChannel();
        
    protected:
        virtual std::optional<Types::Blob> OpenInfo(std::string& nameOut, UInt32 &packetSize, UInt32 &windowSize) = 0;
        virtual void Opened(Types::Blob data) = 0;
        virtual void OpenFailed(UInt32 reason, const std::string& message, const std::string& languageTag) = 0;
        
        virtual void ReceivedEOF(void) { /* Indicates the remote will send no further data */ }
        virtual void ReceivedClose(void) = 0;
        virtual void ReceivedData(Types::Blob data) = 0;
        virtual void ReceivedExtendedData(UInt32 type, Types::Blob data) = 0;
        virtual bool ReceivedRequest(const std::string& request, Types::Blob data) { return false; }
        virtual void ReceivedRequestResponse(bool success) {}
        
        void Send(Types::Blob data);
        void SendExtended(UInt32 type, Types::Blob data);
        void SendEOF(void);
        void Request(const std::string& request, bool wantResponse, std::optional<Types::Blob> extraData);
        void Close(void);
        
    private:
        friend Connection;
        
        void HandleOpen(UInt32 otherChannel, UInt32 windowSize, UInt32 maxPacketSize, Types::Blob data);
        void HandleData(Types::Blob data);
        void HandleExtendedData(UInt32 type, Types::Blob data);
        void HandleWindowAdjust(UInt32 adjust);
        void HandleClose(void);
        void HandleRequest(const std::string& request, bool reply, Types::Blob data);
        
        UInt32 _remoteChannel;
        UInt32 _maxPacketSize;
        UInt32 _localWindowSize;    // How much we're expecting to receive, incremented by us sending window adjust and decremented by received
        UInt32 _remoteWindowSize;   // How much we're allowed to send, incremented by window adjust messages and decremented by send
        
        bool _sentEOF = false;
        bool _sentClose = false;
        
        Connection &_owner;
        IPending::Root _pendings;
        Types::Blob *_pending;
        
        void CheckSend(void);
        void CheckWindow(void);
    };

    /**
     * Interface for providing a type of channel.
     */
    class IChannelProvider
    {
    public:
        virtual ~IChannelProvider() = default;
        
        virtual std::shared_ptr<AChannel> AcceptChannel(std::string channelType, Types::Blob extraData) = 0;
    };
    
    ~Connection();
    
    void HandlePayload(Types::Blob data) override;

    void OpenChannel(std::shared_ptr<AChannel> channel);  // Start an outgoing connection (other side is provider)
    
    void RegisterChannelType(std::string channelType, std::shared_ptr<IChannelProvider> provider);

protected:
    Connection(Transport::Transport& owner);
    
    void BeginConnection(void);

private:
    /**
     * Class to contain all active channels.
     */
    class ChannelList
    {
    private:
        std::vector<std::shared_ptr<AChannel>> _channels;
        
    public:
        std::shared_ptr<AChannel> ChannelFor(UInt32 channel);
        UInt32 Map(std::shared_ptr<AChannel> channel);
        void Unmap(UInt32 channel);
        
        std::vector<std::shared_ptr<AChannel>>::iterator begin(void) { return _channels.begin(); }
        std::vector<std::shared_ptr<AChannel>>::iterator end(void) { return _channels.end(); }
        
    };
    
    ChannelList _channels;
    bool _started = false;
    
    Transport::Transport &_transport;
    
    std::map<std::string, std::shared_ptr<IChannelProvider>> _mappings;
    
    void SendOpenFailure(UInt32 recipientChannel, SSHConnection reason);
};
    
/**
 * SSH server version of the Connection service.
 */
class Server : public Connection, public Core::Server::IServiceProvider
{
public:
    Server(Core::Server& server, std::shared_ptr<Core::Server::IServiceHandler> enabler);
    
    void ServiceRequested(std::string name, std::optional<std::string> username) override;
    
    void HandlePayload(Types::Blob data) override { Connection::HandlePayload(data); }
};

/**
 * SSH client version of the Connection service.
 */
class Client : public Connection, public Core::Client::IService
{
public:
    Client(Core::Client& owner, std::shared_ptr<Core::Client::IEnabler> enabler);

    void Start(void) override;
    
    void HandlePayload(Types::Blob data) override { Connection::HandlePayload(data); }
};

} // namespace minissh::Core::Connection
