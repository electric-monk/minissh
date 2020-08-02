//
//  Connection.cpp
//  minissh
//
//  Created by Colin David Munro on 18/02/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#include <stdlib.h>
#include <memory.h>
#include "Connection.h"
#include "SshNumbers.h"

namespace minissh::Core {

Connection::AChannel::APending::APending(APending **start, APending **end)
{
    _start = start;
    _end = end;
    _next = nullptr;
    _previous = *_end;
    *_end = this;
    if (_previous)
        _previous->_next = this;
    else
        *_start = this;
}

Connection::AChannel::APending::~APending()
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
    
Connection::AChannel::PendingData::PendingData(APending **start, APending **end, Types::Blob data)
:APending(start, end), _data(data)
{
}

UInt32 Connection::AChannel::PendingData::Send(Transport::Transport& sender, UInt32 remoteChannel, UInt32 maximum)
{
    if (maximum == 0)
        return 0;
    Types::Blob packet;
    Types::Writer writer(packet);
    writer.Write(Byte(CHANNEL_DATA));
    writer.Write(remoteChannel);
    UInt32 remaining = _data.Length();
    if (maximum > remaining)
        maximum = remaining;
    writer.Write(maximum);  // Writing length - manually sending a string
    packet.Append(_data.Value(), maximum);
    sender.Send(packet);
    _data.Strip(0, maximum);
    return maximum;
}

bool Connection::AChannel::PendingData::Empty(void)
{
    return _data.Length() == 0;
}

bool Connection::AChannel::PendingData::IgnoreWindow(void)
{
    return false;
}

Connection::AChannel::PendingExtendedData::PendingExtendedData(APending **start, APending **end, UInt32 type, Types::Blob data)
:PendingData(start, end, data)
{
    _type = type;
}

UInt32 Connection::AChannel::PendingExtendedData::Send(Transport::Transport& sender, UInt32 remoteChannel, UInt32 maximum)
{
    if (maximum == 0)
        return 0;
    Types::Blob packet;
    Types::Writer writer(packet);
    writer.Write(Byte(CHANNEL_EXTENDED_DATA));
    writer.Write(remoteChannel);
    writer.Write(_type);
    UInt32 remaining = _data.Length();
    if (maximum > remaining)
        maximum = remaining;
    writer.Write(maximum);  // Writing length - manually sending a string
    packet.Append(_data.Value(), maximum);
    sender.Send(packet);
    _data.Strip(0, maximum);
    return maximum;
}

Connection::AChannel::PendingEOF::PendingEOF(APending **start, APending **end)
:APending(start, end)
{
    _sent = false;
}

UInt32 Connection::AChannel::PendingEOF::Send(Transport::Transport& sender, UInt32 remoteChannel, UInt32 maximum)
{
    Types::Blob packet;
    Types::Writer writer(packet);
    writer.Write(Byte(CHANNEL_EOF));
    writer.Write(remoteChannel);
    sender.Send(packet);
    return 0;
}

bool Connection::AChannel::PendingEOF::Empty(void)
{
    return _sent;
}

bool Connection::AChannel::PendingEOF::IgnoreWindow(void)
{
    return true;
}

std::shared_ptr<Connection::AChannel> Connection::ChannelList::ChannelFor(UInt32 channel)
{
    if (channel >= _channels.size())
        return nullptr;
    return _channels[channel];
}

UInt32 Connection::ChannelList::Map(std::shared_ptr<Connection::AChannel> channel)
{
    // Find a slot
    UInt32 i = 0;
    for (std::shared_ptr<Connection::AChannel>& entry : _channels) {
        if (!entry) {
            entry = channel;
            return i;
        }
        i++;
    }
    // Make more slots
    i = static_cast<UInt32>(_channels.size());
    _channels.push_back(channel);
    return i;
}

void Connection::ChannelList::Unmap(UInt32 channel)
{
    if (channel >= _channels.size())
        return;
    _channels[channel] = nullptr;
}

Connection::AChannel::AChannel(Connection& owner)
:_owner(owner)
{
}

Connection::AChannel::~AChannel()
{
    while (_start)
        delete _start;
}
    
void Connection::AChannel::Send(Types::Blob data)
{
    if (_sentEOF) {
        // error?
        return;
    }
    new PendingData(&_start, &_end, data);
    CheckSend();
}

void Connection::AChannel::SendExtended(UInt32 type, Types::Blob data)
{
    if (_sentEOF) {
        // error?
        return;
    }
    new PendingExtendedData(&_start, &_end, type, data);
    CheckSend();
}

void Connection::AChannel::SendEOF(void)
{
    if (_sentEOF)
        return;
    // Append to the output queue, so all the info makes it first
    new PendingEOF(&_start, &_end);
    CheckSend();
}

void Connection::AChannel::Request(const std::string& request, bool wantResponse, std::optional<Types::Blob> extraData)
{
    Types::Blob packet;
    Types::Writer writer(packet);
    writer.Write(Byte(CHANNEL_REQUEST));
    writer.Write(_remoteChannel);
    writer.WriteString(request);
    writer.Write(wantResponse);
    if (extraData)
        packet.Append(extraData->Value(), extraData->Length());
    _owner._transport.Send(packet);
}

void Connection::AChannel::Close(void)
{
    if (_sentClose)
        return;
    _sentClose = true;
    Types::Blob packet;
    Types::Writer writer(packet);
    writer.Write(Byte(CHANNEL_CLOSE));
    writer.Write(_remoteChannel);
    _owner._transport.Send(packet);
}

void Connection::AChannel::HandleOpen(UInt32 otherChannel, UInt32 windowSize, UInt32 maxPacketSize, Types::Blob data)
{
    _remoteChannel = otherChannel;
    _remoteWindowSize = windowSize;
    _maxPacketSize = maxPacketSize;
    Opened(data);
}

void Connection::AChannel::HandleData(Types::Blob data)
{
    _localWindowSize -= data.Length();
    // TODO: check it's not gone negative
    CheckWindow();
    ReceivedData(data);
}

void Connection::AChannel::HandleExtendedData(UInt32 type, Types::Blob data)
{
    _localWindowSize -= data.Length();
    // TODO: check it's not gone negative
    CheckWindow();
    ReceivedExtendedData(type, data);
}

void Connection::AChannel::HandleWindowAdjust(UInt32 adjust)
{
    _remoteWindowSize += adjust;
    CheckSend();
}

void Connection::AChannel::HandleClose(void)
{
    if (!_sentClose)
        Close();
    ReceivedClose();
}

void Connection::AChannel::HandleRequest(const std::string& request, bool reply, Types::Blob data)
{
    bool result = ReceivedRequest(request, data);
    if (reply) {
        Types::Blob packet;
        Types::Writer writer(packet);
        writer.Write(Byte(result ? CHANNEL_SUCCESS : CHANNEL_FAILURE));
        writer.Write(_remoteChannel);
        _owner._transport.Send(packet);
    }
}

void Connection::AChannel::CheckSend(void)
{
    UInt32 maximum = _maxPacketSize;
    if (maximum > _remoteWindowSize)
        maximum = _remoteWindowSize;
    while ((_start != NULL) && (_remoteWindowSize || _start->IgnoreWindow())) {
        UInt32 sent = _start->Send(_owner._transport, _remoteChannel, maximum);
        if (_start->Empty())
            delete _start;
        _remoteWindowSize -= sent;
    }
}

void Connection::AChannel::CheckWindow(void)
{
    if (_localWindowSize < 16384) {
        Types::Blob packet;
        Types::Writer writer(packet);
        writer.Write(Byte(CHANNEL_WINDOW_ADJUST));
        writer.Write(_remoteChannel);
        writer.Write(UInt32(65536));
        _owner._transport.Send(packet);
        _localWindowSize += 65536;
    }
}

static const Byte packets[] = {CHANNEL_OPEN, CHANNEL_OPEN_CONFIRMATION, CHANNEL_OPEN_FAILURE, CHANNEL_WINDOW_ADJUST, CHANNEL_DATA, CHANNEL_EXTENDED_DATA, CHANNEL_EOF, CHANNEL_CLOSE, CHANNEL_REQUEST, CHANNEL_SUCCESS, CHANNEL_FAILURE};

Connection::Connection(Client& owner, std::shared_ptr<Client::IEnabler> enabler)
:_transport(owner), _running(false)
{
    _transport.RegisterForPackets(this, packets, sizeof(packets) / sizeof(packets[0]));
    enabler->Request("ssh-connection", this);
}

Connection::~Connection()
{
    _transport.UnregisterForPackets(packets, sizeof(packets) / sizeof(packets[0]));
}

void Connection::OpenChannel(std::shared_ptr<AChannel> channel)
{
    // Get init info
    std::string name;
    UInt32 packetSize = 1024;
    UInt32 windowSize = 65536;
    std::optional<Types::Blob> data = channel->OpenInfo(name, packetSize, windowSize);
    if (!name.length())
        return;
    
    // Get channel number
    UInt32 channelIndex = _channels.Map(channel);
    if (!_running)
        return;
    
    // Send request
    Types::Blob packet;
    Types::Writer writer(packet);
    writer.Write(Byte(CHANNEL_OPEN));
    writer.WriteString(name);
    writer.Write(channelIndex);
    writer.Write(windowSize);
    writer.Write(packetSize);
    if (data)
        packet.Append(data->Value(), data->Length());
    _transport.Send(packet);
}

void Connection::Start(void)
{
    _running = true;
    UInt32 i = 0;
    for (std::shared_ptr<Connection::AChannel>& channel : _channels) {
        if (channel) {
            std::string name;
            UInt32 packetSize = 1024;
            UInt32 windowSize = 65536;
            std::optional<Types::Blob> data = channel->OpenInfo(name, packetSize, windowSize);
            Types::Blob packet;
            Types::Writer writer(packet);
            writer.Write(Byte(CHANNEL_OPEN));
            writer.WriteString(name);
            writer.Write(i);
            writer.Write(windowSize);
            writer.Write(packetSize);
            if (data)
                packet.Append(data->Value(), data->Length());
            _transport.Send(packet);
        }
        i++;
    }
}

void Connection::HandlePayload(Types::Blob packet)
{
    Types::Reader reader(packet);
    Byte message = reader.ReadByte();
    switch (message) {
        case CHANNEL_OPEN:  // service provider
            // TODO
            break;
        case CHANNEL_OPEN_CONFIRMATION: // client of service
        {
            UInt32 recipientChannel = reader.ReadUInt32();
            UInt32 senderChannel = reader.ReadUInt32();
            UInt32 windowSize = reader.ReadUInt32();
            UInt32 packetSize = reader.ReadUInt32();
            Types::Blob data = reader.ReadBytes(reader.Remaining());
            std::shared_ptr<AChannel> channel = _channels.ChannelFor(recipientChannel);
            if (channel)
                channel->HandleOpen(senderChannel, windowSize, packetSize, data);
            else
                /* panic? */;
        }
            break;
        case CHANNEL_OPEN_FAILURE: // client of service
        {
            UInt32 recipientChannel = reader.ReadUInt32();
            UInt32 reason = reader.ReadUInt32();
            Types::Blob message = reader.ReadString();
            Types::Blob languageTag = reader.ReadString();
            std::shared_ptr<AChannel> channel = _channels.ChannelFor(recipientChannel);
            if (channel)
                channel->OpenFailed(reason, message.AsString(), languageTag.AsString());
            else
                /* panic? */;
        }
            break;
        case CHANNEL_WINDOW_ADJUST:
        {
            UInt32 recipientChannel = reader.ReadUInt32();
            UInt32 adjustment = reader.ReadUInt32();
            std::shared_ptr<AChannel> channel = _channels.ChannelFor(recipientChannel);
            if (channel)
                channel->HandleWindowAdjust(adjustment);
            else
                /* panic? */;
            break;
        }
        case CHANNEL_DATA:
        {
            UInt32 recipientChannel = reader.ReadUInt32();
            Types::Blob data = reader.ReadString();
            std::shared_ptr<AChannel> channel = _channels.ChannelFor(recipientChannel);
            if (channel)
                channel->HandleData(data);
            else
                /* panic? */;
            break;
        }
        case CHANNEL_EXTENDED_DATA:
        {
            UInt32 recipientChannel = reader.ReadUInt32();
            UInt32 type = reader.ReadUInt32();
            Types::Blob data = reader.ReadString();
            std::shared_ptr<AChannel> channel = _channels.ChannelFor(recipientChannel);
            if (channel)
                channel->HandleExtendedData(type, data);
            else
                /* panic? */;
            break;
        }
        case CHANNEL_EOF:
        {
            UInt32 recipientChannel = reader.ReadUInt32();
            std::shared_ptr<AChannel> channel = _channels.ChannelFor(recipientChannel);
            if (channel)
                channel->ReceivedEOF();
            else
                /* panic? */;
            break;
        }
        case CHANNEL_CLOSE:
        {
            UInt32 recipientChannel = reader.ReadUInt32();
            std::shared_ptr<AChannel> channel = _channels.ChannelFor(recipientChannel);
            if (channel) {
                channel->HandleClose();
                _channels.Unmap(recipientChannel);
            } else
                /* panic? */;
            break;
        }
        case CHANNEL_REQUEST:
        {
            UInt32 recipientChannel = reader.ReadUInt32();
            Types::Blob request = reader.ReadString();
            bool reply = reader.ReadBoolean();
            Types::Blob data = reader.ReadString();
            std::shared_ptr<AChannel> channel = _channels.ChannelFor(recipientChannel);
            if (channel)
                channel->HandleRequest(request.AsString(), reply, data);
            else
                /* panic? */;
            break;
        }
        case CHANNEL_SUCCESS:
        case CHANNEL_FAILURE:
        {
            UInt32 recipientChannel = reader.ReadUInt32();
            std::shared_ptr<AChannel> channel = _channels.ChannelFor(recipientChannel);
            if (channel)
                channel->ReceivedRequestResponse(message == CHANNEL_SUCCESS);
            else
                /* panic? */;
            break;
        }
    }
}

} // namespace minissh::Core
