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

namespace minissh::Core {

class Connection : public Client::Service
{
public:
    class Channel
    {
    public:
        Channel(Connection& owner);
        virtual ~Channel();
        
    protected:
        // Server side
//        virtual UInt32 Open(sshBlob *info, sshString **error) = 0;
        
        // Client side
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
        class Pending
        {
        public:
            Pending(Pending **start, Pending **end);
            virtual ~Pending();
            
            virtual UInt32 Send(Transport::Transport& sender, UInt32 remoteChannel, UInt32 maximum) = 0;
            virtual bool Empty(void) = 0;
            virtual bool IgnoreWindow(void) = 0;
            
        private:
            Pending **_start, **_end;
            Pending *_previous, *_next;
        };
        class PendingData : public Pending
        {
        public:
            PendingData(Pending **start, Pending **end, Types::Blob data);
            UInt32 Send(Transport::Transport& sender, UInt32 remoteChannel, UInt32 maximum) override;
            bool Empty(void) override;
            bool IgnoreWindow(void) override;
        protected:
            Types::Blob _data;
        };
        class PendingExtendedData : public PendingData
        {
        public:
            PendingExtendedData(Pending **start, Pending **end, UInt32 type, Types::Blob data);
            UInt32 Send(Transport::Transport& sender, UInt32 remoteChannel, UInt32 maximum) override;
        protected:
            UInt32 _type;
        };
        class PendingEOF : public Pending
        {
        public:
            PendingEOF(Pending **start, Pending **end);
            UInt32 Send(Transport::Transport& sender, UInt32 remoteChannel, UInt32 maximum) override;
            bool Empty(void) override;
            bool IgnoreWindow(void) override;
        protected:
            bool _sent;
        };

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
        Pending *_start = nullptr;
        Pending *_end = nullptr;
        Types::Blob *_pending;
        
        void CheckSend(void);
        void CheckWindow(void);
    };

    Connection(Client& owner, std::shared_ptr<Client::Enabler> enabler);
    ~Connection();

    void OpenChannel(std::shared_ptr<Channel> channel);  // Start an outgoing connection (other side is provider)

    // TODO: Server constructor and plumbing
//    void AddService(sshChannelFactory *factory);    // Start an incoming connection (this side is provider)
    
    void Start(void);
    void HandlePayload(Types::Blob data);
    
private:
    class ChannelList
    {
    private:
        std::vector<std::shared_ptr<Connection::Channel>> _channels;
        
    public:
        std::shared_ptr<Connection::Channel> ChannelFor(UInt32 channel);
        UInt32 Map(std::shared_ptr<Connection::Channel> channel);
        void Unmap(UInt32 channel);
        
        std::vector<std::shared_ptr<Connection::Channel>>::iterator begin(void) { return _channels.begin(); }
        std::vector<std::shared_ptr<Connection::Channel>>::iterator end(void) { return _channels.end(); }
        
    };

    ChannelList _channels;
    bool _running;

    Transport::Transport &_transport;
};

} // namespace minissh::Core
