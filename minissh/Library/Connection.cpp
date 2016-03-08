//
//  Connection.cpp
//  minissh
//
//  Created by Colin David Munro on 18/02/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#include <stdlib.h>
#include <memory.h>
#include "Connection.h"
#include "SshNumbers.h"

namespace sshConnection_Internal {
    class Pending
    {
    public:
        Pending(Pending **start, Pending **end)
        {
            _start = start;
            _end = end;
            _next = NULL;
            _previous = *_end;
            *_end = this;
            if (_previous)
                _previous->_next = this;
            else
                *_start = this;
        }
        
        virtual ~Pending()
        {
            if (_next)
                _next->_previous = _previous;
            if (_previous)
                _previous->_next = _next;
            if (*_start == this)
                *_start = _next;
            if (*_end == this)
                *_end = _previous;
        }
        
        virtual UInt32 Send(sshTransport *sender, UInt32 remoteChannel, UInt32 maximum) = 0;
        virtual bool Empty(void) = 0;
        virtual bool IgnoreWindow(void) = 0;
        
    private:
        Pending **_start, **_end;
        Pending *_previous, *_next;
    };

    class PendingData : public Pending
    {
    public:
        PendingData(Pending **start, Pending **end, sshBlob *data)
        :Pending(start, end)
        {
            _data = data;
            _data->AddRef();
        }
        
        ~PendingData()
        {
            _data->Release();
        }
        
        UInt32 Send(sshTransport *sender, UInt32 remoteChannel, UInt32 maximum)
        {
            if (maximum == 0)
                return 0;
            sshBlob *packet = new sshBlob();
            sshWriter writer(packet);
            writer.Write(Byte(SSH_MSG_CHANNEL_DATA));
            writer.Write(remoteChannel);
            UInt32 remaining = _data->Length();
            if (maximum > remaining)
                maximum = remaining;
            writer.Write(maximum);  // Writing length - manually sending a string
            packet->Append(_data->Value(), maximum);
            sender->Send(packet);
            packet->Release();
            _data->Strip(0, maximum);
            return maximum;
        }
        
        bool Empty(void)
        {
            return _data->Length() == 0;
        }
        
        bool IgnoreWindow(void)
        {
            return false;
        }
        
    protected:
        sshBlob *_data;
    };

    class PendingExtendedData : public PendingData
    {
    public:
        PendingExtendedData(Pending **start, Pending **end, UInt32 type, sshBlob *data)
        :PendingData(start, end, data)
        {
            _type = type;
        }
        
        UInt32 Send(sshTransport *sender, UInt32 remoteChannel, UInt32 maximum)
        {
            if (maximum == 0)
                return 0;
            sshBlob *packet = new sshBlob();
            sshWriter writer(packet);
            writer.Write(Byte(SSH_MSG_CHANNEL_EXTENDED_DATA));
            writer.Write(remoteChannel);
            writer.Write(_type);
            UInt32 remaining = _data->Length();
            if (maximum > remaining)
                maximum = remaining;
            writer.Write(maximum);  // Writing length - manually sending a string
            packet->Append(_data->Value(), maximum);
            sender->Send(packet);
            packet->Release();
            _data->Strip(0, maximum);
            return maximum;
        }
        
    protected:
        UInt32 _type;
    };

    class PendingEOF : public Pending
    {
    public:
        PendingEOF(Pending **start, Pending **end)
        :Pending(start, end)
        {
            _sent = false;
        }
        
        UInt32 Send(sshTransport *sender, UInt32 remoteChannel, UInt32 maximum)
        {
            sshBlob *packet = new sshBlob();
            sshWriter writer(packet);
            writer.Write(Byte(SSH_MSG_CHANNEL_EOF));
            writer.Write(remoteChannel);
            sender->Send(packet);
            packet->Release();
            return 0;
        }
        
        bool Empty(void)
        {
            return _sent;
        }
        
        bool IgnoreWindow(void)
        {
            return true;
        }

    protected:
        bool _sent;
    };
    
    class ChannelList
    {
    private:
        sshConnection::sshChannel **_channels;
        UInt32 _max;
        
    public:
        ChannelList()
        {
            _max = 1;
            _channels = new sshConnection::sshChannel*[_max];
            for (UInt32 i = 0; i < _max; i++)
                _channels[i] = NULL;
        }
        
        ~ChannelList()
        {
            for (UInt32 i = 0; i < _max; i++) {
                if (_channels[i] != NULL)
                    _channels[i]->Release();
            }
            delete[] _channels;
        }
        
        sshConnection::sshChannel* ChannelFor(UInt32 channel)
        {
            if (channel >= _max)
                return NULL;
            return _channels[channel];
        }
        
        UInt32 Map(sshConnection::sshChannel *channel)
        {
            // Find a slot
            for (UInt32 i = 0; i < _max; i++) {
                if (_channels[i] == NULL) {
                    _channels[i] = channel;
                    channel->AddRef();
                    return i;
                }
            }
            // Make more slots
            UInt32 newMax = _max * 2;
            sshConnection::sshChannel **newChannels = new sshConnection::sshChannel*[newMax];
            memcpy(newChannels, _channels, sizeof(sshConnection::sshChannel*) * _max);
            for (UInt32 i = _max + 1; i < newMax; i++)
                newChannels[i] = NULL;
            delete[] _channels;
            _channels = newChannels;
            UInt32 result = _max;
            _max = newMax;
            // Pick the next
            _channels[result] = channel;
            channel->AddRef();
            return result;
        }
        
        void Unmap(UInt32 channel)
        {
            if (channel >= _max)
                return;
            if (_channels[channel] == NULL)
                return;
            _channels[channel]->Release();
            _channels[channel] = NULL;
        }
        
        UInt32 HighestChannel(void)
        {
            return _max;
        }
    };
}

sshConnection::sshChannel::sshChannel(sshConnection *owner)
{
    _owner = owner;
    _sentEOF = false;
    _sentClose = false;
    _start = NULL;
    _end = NULL;
}

void sshConnection::sshChannel::Send(sshBlob *data)
{
    if (_sentEOF) {
        // error?
        return;
    }
    new sshConnection_Internal::PendingData(&_start, &_end, data);
    CheckSend();
}

void sshConnection::sshChannel::SendExtended(UInt32 type, sshBlob *data)
{
    if (_sentEOF) {
        // error?
        return;
    }
    new sshConnection_Internal::PendingExtendedData(&_start, &_end, type, data);
    CheckSend();
}

void sshConnection::sshChannel::SendEOF(void)
{
    if (_sentEOF)
        return;
    // Append to the output queue, so all the info makes it first
    new sshConnection_Internal::PendingEOF(&_start, &_end);
    CheckSend();
}

void sshConnection::sshChannel::Request(sshString *request, bool wantResponse, sshBlob *extraData)
{
    sshBlob *packet = new sshBlob();
    sshWriter writer(packet);
    writer.Write(Byte(SSH_MSG_CHANNEL_REQUEST));
    writer.Write(_remoteChannel);
    writer.Write(request);
    writer.Write(wantResponse);
    if (extraData)
        packet->Append(extraData->Value(), extraData->Length());
    _owner->transport->Send(packet);
    packet->Release();
}

void sshConnection::sshChannel::Close(void)
{
    if (_sentClose)
        return;
    _sentClose = true;
    sshBlob *packet = new sshBlob();
    sshWriter writer(packet);
    writer.Write(Byte(SSH_MSG_CHANNEL_CLOSE));
    writer.Write(_remoteChannel);
    _owner->transport->Send(packet);
    packet->Release();
}

void sshConnection::sshChannel::HandleOpen(UInt32 otherChannel, UInt32 windowSize, UInt32 maxPacketSize, sshBlob *data)
{
    _remoteChannel = otherChannel;
    _remoteWindowSize = windowSize;
    _maxPacketSize = maxPacketSize;
    Opened(data);
}

void sshConnection::sshChannel::HandleData(sshBlob *data)
{
    _localWindowSize -= data->Length();
    // TODO: check it's not gone negative
    CheckWindow();
    ReceivedData(data);
}

void sshConnection::sshChannel::HandleExtendedData(UInt32 type, sshBlob *data)
{
    _localWindowSize -= data->Length();
    // TODO: check it's not gone negative
    CheckWindow();
    ReceivedExtendedData(type, data);
}

void sshConnection::sshChannel::HandleWindowAdjust(UInt32 adjust)
{
    _remoteWindowSize += adjust;
    CheckSend();
}

void sshConnection::sshChannel::HandleClose(void)
{
    if (!_sentClose)
        Close();
    ReceivedClose();
}

void sshConnection::sshChannel::HandleRequest(sshString *request, bool reply, sshBlob *data)
{
    bool result = ReceivedRequest(request, data);
    if (reply) {
        sshBlob *packet = new sshBlob();
        sshWriter writer(packet);
        writer.Write(Byte(result ? SSH_MSG_CHANNEL_SUCCESS : SSH_MSG_CHANNEL_FAILURE));
        writer.Write(_remoteChannel);
        _owner->transport->Send(packet);
        packet->Release();
    }
}

void sshConnection::sshChannel::CheckSend(void)
{
    UInt32 maximum = _maxPacketSize;
    if (maximum > _remoteWindowSize)
        maximum = _remoteWindowSize;
    while ((_start != NULL) && (_remoteWindowSize || _start->IgnoreWindow())) {
        UInt32 sent = _start->Send(_owner->transport, _remoteChannel, maximum);
        if (_start->Empty())
            delete _start;
        _remoteWindowSize -= sent;
    }
}

void sshConnection::sshChannel::CheckWindow(void)
{
    if (_localWindowSize < 16384) {
        sshBlob *packet = new sshBlob();
        sshWriter writer(packet);
        writer.Write(Byte(SSH_MSG_CHANNEL_WINDOW_ADJUST));
        writer.Write(_remoteChannel);
        writer.Write(UInt32(65536));
        _owner->transport->Send(packet);
        packet->Release();
        _localWindowSize += 65536;
    }
}

static const Byte packets[] = {SSH_MSG_CHANNEL_OPEN, SSH_MSG_CHANNEL_OPEN_CONFIRMATION, SSH_MSG_CHANNEL_OPEN_FAILURE, SSH_MSG_CHANNEL_WINDOW_ADJUST, SSH_MSG_CHANNEL_DATA, SSH_MSG_CHANNEL_EXTENDED_DATA, SSH_MSG_CHANNEL_EOF, SSH_MSG_CHANNEL_CLOSE, SSH_MSG_CHANNEL_REQUEST, SSH_MSG_CHANNEL_SUCCESS, SSH_MSG_CHANNEL_FAILURE};

sshConnection::sshConnection(sshClient *owner, sshClient::Enabler *enabler)
{
    transport = owner;
    transport->RegisterForPackets(this, packets, sizeof(packets) / sizeof(packets[0]));
    _running = false;
    enabler->Request("ssh-connection", this);
    _channels = new sshConnection_Internal::ChannelList();
}

sshConnection::~sshConnection()
{
    transport->UnregisterForPackets(packets, sizeof(packets) / sizeof(packets[0]));
    delete _channels;
}

void sshConnection::OpenChannel(sshChannel *channel)
{
    // Get init info
    sshBlob *data;
    sshString *name = NULL;
    UInt32 packetSize = 1024;
    UInt32 windowSize = 65536;
    data = channel->OpenInfo(&name, &packetSize, &windowSize);
    if (!name)
        return;
    
    // Get channel number
    UInt32 channelIndex = _channels->Map(channel);
    if (!_running)
        return;
    
    // Send request
    sshBlob *packet = new sshBlob();
    sshWriter writer(packet);
    writer.Write(Byte(SSH_MSG_CHANNEL_OPEN));
    writer.Write(name);
    writer.Write(channelIndex);
    writer.Write(windowSize);
    writer.Write(packetSize);
    if (data)
        packet->Append(data->Value(), data->Length());
    transport->Send(packet);
    packet->Release();
}

void sshConnection::Start(void)
{
    _running = true;
    for (UInt32 i = 0; i < _channels->HighestChannel(); i++) {
        sshConnection::sshChannel *channel = _channels->ChannelFor(i);
        if (channel == NULL)
            continue;
        
        sshBlob *data;
        sshString *name = NULL;
        UInt32 packetSize = 1024;
        UInt32 windowSize = 65536;
        data = channel->OpenInfo(&name, &packetSize, &windowSize);
        sshBlob *packet = new sshBlob();
        sshWriter writer(packet);
        writer.Write(Byte(SSH_MSG_CHANNEL_OPEN));
        writer.Write(name);
        writer.Write(i);
        writer.Write(windowSize);
        writer.Write(packetSize);
        if (data)
            packet->Append(data->Value(), data->Length());
        transport->Send(packet);
        packet->Release();
    }
}

void sshConnection::HandlePayload(sshBlob *packet)
{
    sshReader reader(packet);
    Byte message = reader.ReadByte();
    switch (message) {
        case SSH_MSG_CHANNEL_OPEN:  // service provider
            // TODO
            break;
        case SSH_MSG_CHANNEL_OPEN_CONFIRMATION: // client of service
        {
            UInt32 recipientChannel = reader.ReadUInt32();
            UInt32 senderChannel = reader.ReadUInt32();
            UInt32 windowSize = reader.ReadUInt32();
            UInt32 packetSize = reader.ReadUInt32();
            sshBlob *data = reader.ReadBytes(reader.Remaining());
            sshChannel *channel = _channels->ChannelFor(recipientChannel);
            if (channel)
                channel->HandleOpen(senderChannel, windowSize, packetSize, data);
            else
                /* panic? */;
        }
            break;
        case SSH_MSG_CHANNEL_OPEN_FAILURE: // client of service
        {
            UInt32 recipientChannel = reader.ReadUInt32();
            UInt32 reason = reader.ReadUInt32();
            sshString *message = reader.ReadString();
            sshString *languageTag = reader.ReadString();
            sshChannel *channel = _channels->ChannelFor(recipientChannel);
            if (channel)
                channel->OpenFailed(reason, message, languageTag);
            else
                /* panic? */;
        }
            break;
        case SSH_MSG_CHANNEL_WINDOW_ADJUST:
        {
            UInt32 recipientChannel = reader.ReadUInt32();
            UInt32 adjustment = reader.ReadUInt32();
            sshChannel *channel = _channels->ChannelFor(recipientChannel);
            if (channel)
                channel->HandleWindowAdjust(adjustment);
            else
                /* panic? */;
            break;
        }
        case SSH_MSG_CHANNEL_DATA:
        {
            UInt32 recipientChannel = reader.ReadUInt32();
            sshString *data = reader.ReadString();
            sshChannel *channel = _channels->ChannelFor(recipientChannel);
            if (channel)
                channel->HandleData(data->AsBlob());
            else
                /* panic? */;
            break;
        }
        case SSH_MSG_CHANNEL_EXTENDED_DATA:
        {
            UInt32 recipientChannel = reader.ReadUInt32();
            UInt32 type = reader.ReadUInt32();
            sshString *data = reader.ReadString();
            sshChannel *channel = _channels->ChannelFor(recipientChannel);
            if (channel)
                channel->HandleExtendedData(type, data->AsBlob());
            else
                /* panic? */;
            break;
        }
        case SSH_MSG_CHANNEL_EOF:
        {
            UInt32 recipientChannel = reader.ReadUInt32();
            sshChannel *channel = _channels->ChannelFor(recipientChannel);
            if (channel)
                channel->ReceivedEOF();
            else
                /* panic? */;
            break;
        }
        case SSH_MSG_CHANNEL_CLOSE:
        {
            UInt32 recipientChannel = reader.ReadUInt32();
            sshChannel *channel = _channels->ChannelFor(recipientChannel);
            if (channel) {
                channel->HandleClose();
                _channels->Unmap(recipientChannel);
            } else
                /* panic? */;
            break;
        }
        case SSH_MSG_CHANNEL_REQUEST:
        {
            UInt32 recipientChannel = reader.ReadUInt32();
            sshString *request = reader.ReadString();
            bool reply = reader.ReadBoolean();
            sshString *data = reader.ReadString();
            sshChannel *channel = _channels->ChannelFor(recipientChannel);
            if (channel)
                channel->HandleRequest(request, reply, data->AsBlob());
            else
                /* panic? */;
            break;
        }
        case SSH_MSG_CHANNEL_SUCCESS:
        case SSH_MSG_CHANNEL_FAILURE:
        {
            UInt32 recipientChannel = reader.ReadUInt32();
            sshChannel *channel = _channels->ChannelFor(recipientChannel);
            if (channel)
                channel->ReceivedRequestResponse(message == SSH_MSG_CHANNEL_SUCCESS);
            else
                /* panic? */;
            break;
        }
    }
}
