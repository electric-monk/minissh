//
//  Connection.h
//  minissh
//
//  Created by Colin David Munro on 18/02/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#ifndef __minissh__Connection__
#define __minissh__Connection__

#include "Transport.h"
#include "Client.h"

namespace sshConnection_Internal {
    class Pending;
    class ChannelList;
}

class sshConnection : public sshClient::Service
{
public:
    class sshChannel : public sshObject
    {
    public:
        sshChannel(sshConnection *owner);
        
    protected:
        // Server side
//        virtual UInt32 Open(sshBlob *info, sshString **error) = 0;
        
        // Client side
        virtual sshBlob* OpenInfo(sshString **nameOut, UInt32 *packetSize, UInt32 *windowSize) = 0;
        virtual void Opened(sshBlob *data) = 0;
        virtual void OpenFailed(UInt32 reason, sshString *message, sshString *languageTag) = 0;
        
        virtual void ReceivedEOF(void) { /* Indicates the remote will send no further data */ }
        virtual void ReceivedClose(void) = 0;
        virtual void ReceivedData(sshBlob *data) = 0;
        virtual void ReceivedExtendedData(UInt32 type, sshBlob *data) = 0;
        virtual bool ReceivedRequest(sshString *request, sshBlob *data) { return false; }
        virtual void ReceivedRequestResponse(bool success) {}
        
        void Send(sshBlob *data);
        void SendExtended(UInt32 type, sshBlob *data);
        void SendEOF(void);
        void Request(sshString *request, bool wantResponse, sshBlob *extraData);
        void Close(void);
    private:
        friend sshConnection;
        void HandleOpen(UInt32 otherChannel, UInt32 windowSize, UInt32 maxPacketSize, sshBlob *data);
        void HandleData(sshBlob *data);
        void HandleExtendedData(UInt32 type, sshBlob *data);
        void HandleWindowAdjust(UInt32 adjust);
        void HandleClose(void);
        void HandleRequest(sshString *request, bool reply, sshBlob *data);
        
        UInt32 _remoteChannel;
        UInt32 _maxPacketSize;
        UInt32 _localWindowSize;    // How much we're expecting to receive, incremented by us sending window adjust and decremented by received
        UInt32 _remoteWindowSize;   // How much we're allowed to send, incremented by window adjust messages and decremented by send
        
        bool _sentEOF, _sentClose;
        
        sshConnection *_owner;
        sshConnection_Internal::Pending *_start, *_end;
        sshBlob *_pending;
        
        void CheckSend(void);
        void CheckWindow(void);
    };

    sshConnection(sshClient *owner, sshClient::Enabler *enabler);
    void OpenChannel(sshChannel *channel);  // Start an outgoing connection (other side is provider)

    // TODO: Server constructor and plumbing
//    void AddService(sshChannelFactory *factory);    // Start an incoming connection (this side is provider)
    
    void Start(void);
    void HandlePayload(sshBlob *data);
    
    sshDictionary *supportedServices;
    sshTransport *transport;
    
protected:
    ~sshConnection();
    
private:
    sshConnection_Internal::ChannelList *_channels;
    bool _running;
};

#endif /* defined(__minissh__Connection__) */
