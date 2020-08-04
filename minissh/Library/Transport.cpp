//
//  Transport.cpp
//  minissh
//
//  Created by Colin David Munro on 10/01/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "Transport.h"
#include "SshNumbers.h"
#include "Maths.h"
#include "RSA.h"
#include "Hash.h"

#ifdef DEBUG_LOG_TRANSFER_INFO
static void TestPrint(char c, const std::string& line)
{
    fprintf(stdout, "%c> %s\n", c, line.c_str());
}
#else
#define TestPrint(x, y)
#endif

namespace minissh::Transport {

namespace {

// This class allows the transport to start up in an unencrypted mode without treating it as a special case
class NoEncryption : public IEncryptionAlgorithm
{
public:
    NoEncryption()
    {
    }
    
    int BlockSize(void) override
    {
        return 8;
    }
    
    Types::Blob Encrypt(Types::Blob data) override
    {
        return data;
    }
    
    Types::Blob Decrypt(Types::Blob data) override
    {
        return data;
    }
};

class NoHmac : public IHMACAlgorithm
{
public:
    NoHmac()
    {
    }
    
    Types::Blob Generate(Types::Blob packet) override
    {
        return Types::Blob();
    }
    
    int Length(void) override
    {
        return 0;
    }
};

} // namespace
    
namespace Internal {
    TransportInfo::TransportInfo()
    {
    }
    
    TransportInfo::~TransportInfo()
    {
        Reset();
    }
    
    void TransportInfo::Reset(void)
    {
        // TODO
    }
    
    class Handler
    {
    public:
        Handler(Transport& owner)
        :_owner(owner)
        {
        }
    
        virtual void HandleMoreData(UInt32 previousLength) = 0;
        
    protected:
        Transport &_owner;
    };
    
    const char* ssh = "SSH-";
    const char* ssh_ident = "SSH-2.0-miceSSH_1.0";

    static bool MatchStringStart(const std::string& first, const char *second, int secondLength)
    {
        const char *bytes = first.c_str();
        int bytesLength = first.length();
        if (bytesLength < secondLength)
            return false;
        for (int i = 0; i < secondLength; i++) {
            if (bytes[i] != second[i])
                return false;
        }
        return true;
    }
    
    class Initialiser : public Handler
    {
    public:
        // Read in strings until we get the SSH initialisation string
        
        Initialiser(Transport& owner)
        :Handler(owner)
        {
        }
        
        void HandleMoreData(UInt32 previousLength)
        {
            while (true) {
                std::optional<std::string> line = _owner.inputBuffer.FindLine();
                if (!line)
                    return;
                TestPrint('S', *line);
                if (MatchStringStart(*line, ssh, (int)strlen(ssh))) {
                    _owner.InitialiseSSH(*line, _message);
                    return;
                } else {
                    _message.push_back(*line);
                }
            }
        }
        
    private:
        std::vector<std::string> _message;
    };
    
    class BlockReceiver : public Handler
    {
    public:
        // Read in blocks of a specific size
        
        BlockReceiver(Transport& owner)
        :Handler(owner)
        {
        }
        
        void HandleMoreData(UInt32 previousLength)
        {
            int blockSize = _owner.GetIncomingEncryption()->BlockSize();
            int amount;
            while (_owner.inputBuffer.Length() >= (amount = NextRead(blockSize))) {
                if (!_packet)
                    _packet.emplace(Packet(_owner));
                _packet->Append(_owner.inputBuffer.Value(), amount);
                _owner.inputBuffer.Strip(0, amount);
                if (_packet->Satisfied()) {
                    _owner.HandlePacket(*_packet);
                    _packet = std::nullopt;
                }
            }
        }
        
    private:
        std::optional<Packet> _packet;
        
        UInt32 NextRead(UInt32 blockSize)
        {
            if (!_packet)
                return blockSize;
            return std::min(_packet->Requires(), blockSize);
        }
    };
    
    static std::optional<std::string> CheckGuess(const std::vector<std::string>& client, const std::vector<std::string>& server)
    {
        std::string clientGuess = client.front();
        if (clientGuess.compare(server.front()) == 0)
            return clientGuess;
        return {};
    }
    
    static std::optional<std::string> FindMatch(const std::vector<std::string>& client, const std::vector<std::string>& server)
    {
        for (auto const& name : client) {
            for (auto const& sname : server) {
                if (name.compare(sname) == 0)
                    return name;
            }
        }
        return {};
    }
    
    template<class K, class V> std::vector<K> AllKeys(const std::map<K, V>& input)
    {
        std::vector<K> result;
        result.reserve(input.size());
        for (auto const& entry : input)
            result.push_back(entry.first);
        return result;
    }
    
    template<class C> std::optional<std::string> FindMatch(Mode mode, const std::vector<std::string>& remoteList, const std::map<std::string, C>& localList)
    {
        std::vector<std::string> localListKeys = AllKeys(localList);
        if (mode == Server)
            return FindMatch(remoteList, localListKeys);
        else
            return FindMatch(localListKeys, remoteList);
    }
    
    class KexHandler : public IMessageHandler
    {
    private:
        Transport &_owner;
        Mode _mode;
        bool _expectingInit;
        std::shared_ptr<KeyExchanger> _activeExchanger;
        
        void SendKex(void)
        {
            if (_expectingInit)
                return;
            Types::Blob output;
            Types::Writer writer(output);
            writer.Write(KEXINIT);
            // Cookie
            for (int i = 0; i < 4; i++)
                writer.Write(UInt32(_owner.random.Random()));
            // All the lists
            writer.Write(AllKeys(_owner.configuration.supportedKeyExchanges));
            writer.Write(AllKeys(_owner.configuration.serverHostKeyAlgorithms));
            writer.Write(AllKeys(_owner.configuration.encryptionAlgorithms_clientToServer));
            writer.Write(AllKeys(_owner.configuration.encryptionAlgorithms_serverToClient));
            writer.Write(AllKeys(_owner.configuration.macAlgorithms_clientToServer));
            writer.Write(AllKeys(_owner.configuration.macAlgorithms_serverToClient));
            writer.Write(AllKeys(_owner.configuration.compressionAlgorithms_clientToServer));
            writer.Write(AllKeys(_owner.configuration.compressionAlgorithms_serverToClient));
            writer.Write(AllKeys(_owner.configuration.languages_clientToServer));
            writer.Write(AllKeys(_owner.configuration.languages_serverToClient));
            writer.Write(bool(false));  // TODO: guesses
            writer.Write(UInt32(0));    // Reserved
            
            _owner.local.kexPayload = output;
            
            _expectingInit = true;
            _owner.Send(output);
        }
    public:
        KexHandler(Transport& owner, Mode mode)
        :_owner(owner), _mode(mode)
        {
            _expectingInit = false;
            
            const Byte messages[] = {KEXINIT, NEWKEYS};
            _owner.RegisterForPackets(this, messages, sizeof(messages) / sizeof(messages[0]));
        }
        
        ~KexHandler()
        {
            const Byte messages[] = {KEXINIT, NEWKEYS};
            _owner.UnregisterForPackets(messages, sizeof(messages) / sizeof(messages[0]));
        }

        void HandlePayload(Types::Blob data) override
        {
            Types::Reader reader(data);
            
            switch (reader.ReadByte()) {
                case KEXINIT:
                {
                    // Store the remote's payload
                    _owner.remote.kexPayload = data;
                    // Get values
                    reader.SkipBytes(16);   // Cookie
                    std::vector<std::string> kexAlgorithms = reader.ReadNameList();  // Kex Algorithms
                    std::vector<std::string> hostKeyAlgorithms = reader.ReadNameList();  // Server Host Key Algorithms
                    std::vector<std::string> encryptionAlgorithms_C2S = reader.ReadNameList();  // encryption (C2S)
                    std::vector<std::string> encryptionAlgorithms_S2C = reader.ReadNameList();  // encryption (S2C)
                    std::vector<std::string> mac_C2S = reader.ReadNameList();  // MAC (C2S)
                    std::vector<std::string> mac_S2C = reader.ReadNameList();  // MAC (S2C)
                    std::vector<std::string> compression_C2S = reader.ReadNameList();  // Compression (C2S)
                    std::vector<std::string> compression_S2C = reader.ReadNameList();  // Compression (S2C)
                    std::vector<std::string> language_C2S = reader.ReadNameList();  // Language (C2S)
                    std::vector<std::string> language_S2C = reader.ReadNameList();  // Language (S2C)
                    bool kex_follows = reader.ReadBoolean();   // First KEX packet follows
                    // Reply, if necessary
                    if (!_expectingInit)
                        SendKex();
                    // Do something about it
                    std::optional<std::string> kexAlgo;
                    if (kex_follows) {
                        kexAlgo = CheckGuess(kexAlgorithms, AllKeys(_owner.configuration.supportedKeyExchanges));
                        if (!kexAlgo)
                            _owner.SkipPacket();
                    }
                    if (!kexAlgo)
                        kexAlgo = FindMatch(_mode, kexAlgorithms, _owner.configuration.supportedKeyExchanges);
                    if (!kexAlgo) {
                        _owner.Panic(Transport::PanicReason::NoMatchingAlgorithm);
                        return;
                    }
                    // Find the other algorithms (less complicated)
                    selectedEncryptionToClient = FindMatch(_mode, encryptionAlgorithms_S2C, _owner.configuration.encryptionAlgorithms_serverToClient);
                    selectedEncryptionToServer = FindMatch(_mode, encryptionAlgorithms_C2S, _owner.configuration.encryptionAlgorithms_clientToServer);
                    selectedMACToClient = FindMatch(_mode, mac_S2C, _owner.configuration.macAlgorithms_serverToClient);
                    selectedMACToServer = FindMatch(_mode, mac_C2S, _owner.configuration.macAlgorithms_clientToServer);
                    selectedCompressionToClient = FindMatch(_mode, compression_S2C, _owner.configuration.compressionAlgorithms_serverToClient);
                    selectedCompressionToServer = FindMatch(_mode, compression_C2S, _owner.configuration.compressionAlgorithms_clientToServer);
                    if (!(selectedCompressionToClient && selectedCompressionToServer && selectedEncryptionToClient && selectedEncryptionToServer && selectedMACToClient && selectedMACToServer)) {
                        _owner.Panic(Transport::PanicReason::NoMatchingAlgorithm);
                        return;
                    }
                    // Select host key algorithm (TODO: this should be done in conjunction with kex)
                    std::optional<std::string> hostKeyAlgo = FindMatch(_mode, hostKeyAlgorithms, _owner.configuration.serverHostKeyAlgorithms);
                    if (!hostKeyAlgo) {
                        _owner.Panic(Transport::PanicReason::NoMatchingAlgorithm);
                        return;
                    }
                    // Start
                    _owner.hostKeyAlgorithm = _owner.configuration.serverHostKeyAlgorithms.at(*hostKeyAlgo)->Create(_owner, _mode);
                    _activeExchanger = _owner.configuration.supportedKeyExchanges.at(*kexAlgo)->Create(_owner, _mode);
                    _owner.keyExchanger = _activeExchanger;
                    _activeExchanger->Start();
                }
                    break;
                case NEWKEYS:
                    _expectingInit = false;
                    // New keys ready to go, all incoming messages should now be using the new algorithms
                    _owner.ResetAlgorithms(false);
                    break;
            }
        }
        
        std::optional<std::string> selectedEncryptionToServer;
        std::optional<std::string> selectedEncryptionToClient;
        std::optional<std::string> selectedMACToServer;
        std::optional<std::string> selectedMACToClient;
        std::optional<std::string> selectedCompressionToServer;
        std::optional<std::string> selectedCompressionToClient;
    };
    
} // namespace

std::string Transport::StringForPanicReason(PanicReason reason)
{
    switch (reason) {
        case PanicReason::OutOfRange:
            return "Out of range";
        case PanicReason::InvalidMessage:
            return "Invalid message";
        case PanicReason::NoMatchingAlgorithm:
            return "No matching algorithm";
        case PanicReason::BadHostKey:
            return "Bad host key";
        case PanicReason::BadSignature:
            return "Bad signature";
        case PanicReason::NoHostKey:
            return "No host key";
    }
}
    
Packet::Packet(Transport& owner)
:_owner(owner)
{
}

void Packet::Append(const Byte *bytes, int length)
{
    Blob::Append(bytes, length);
    // Hacky
    if (_requiredBlocks && (_decodedBlocks >= _requiredBlocks))
        return;
    std::shared_ptr<IEncryptionAlgorithm> decrypter = _owner.GetIncomingEncryption();
    int blockSize = decrypter->BlockSize();
    Blob chunk;
    int offset = _decodedBlocks * blockSize;
    while ((!_requiredBlocks || (_decodedBlocks < _requiredBlocks)) && ((offset + blockSize) <= Length())) {
        chunk.Reset();
        chunk.Append(Value() + offset, blockSize);
        Blob decoded = decrypter->Decrypt(chunk);
        memcpy((void*)(Value() + offset), decoded.Value(), blockSize);
        _decodedBlocks++;
        if (!_requiredBlocks)
            _requiredBlocks = (PacketLength() + sizeof(UInt32)) / blockSize;
        offset += blockSize;
    }
}

bool Packet::Satisfied(void)
{
    std::shared_ptr<IEncryptionAlgorithm> decrypter = _owner.GetIncomingEncryption();
    std::shared_ptr<IHMACAlgorithm> mac = _owner.GetIncomingHMAC();
    if (Length() < decrypter->BlockSize())
        return false;
    return Length() == PacketLength() + sizeof(UInt32) + mac->Length();
}

UInt32 Packet::Requires(void)
{
    std::shared_ptr<IEncryptionAlgorithm> decrypter = _owner.GetIncomingEncryption();
    UInt32 blockSize = decrypter->BlockSize();
    if (Length() < blockSize)
        return blockSize;
    std::shared_ptr<IHMACAlgorithm> mac = _owner.GetIncomingHMAC();
    return PacketLength() + sizeof(UInt32) + mac->Length() - Length();
}

UInt32 Packet::PacketLength(void) const
{
    return Types::Reader(*this).ReadUInt32();
}

UInt32 Packet::PaddingLength(void) const
{
    Types::Reader reader(*this);
    reader.ReadUInt32();    // Skip packet length
    return reader.ReadByte();
}

Types::Blob Packet::Payload(void) const
{
    std::shared_ptr<IEncryptionAlgorithm> decrypter = _owner.GetIncomingEncryption();
    if (Length() < decrypter->BlockSize())
        throw new std::runtime_error("Packet does not contain at least a block");
    Types::Reader reader(*this);
    UInt32 length = reader.ReadUInt32();
    length -= reader.ReadByte();
    length--;
    if (Length() < (length + sizeof(UInt32)))
        throw new std::runtime_error("Packet is missing data");
    return reader.ReadBytes((int)length);
}

Types::Blob Packet::Padding(void) const
{
    if (Length() < (PacketLength() + sizeof(UInt32)))
        throw new std::runtime_error("Packet does not contain enough data");
    Types::Reader reader(*this);
    UInt32 length = reader.ReadUInt32();
    length -= reader.ReadByte();
    length--;
    reader.SkipBytes((int)length);
    return reader.ReadBytes((int)length);
}

Types::Blob Packet::MAC(void) const
{
    std::shared_ptr<IHMACAlgorithm> mac = _owner.GetIncomingHMAC();
    if (Length() < (PacketLength() + mac->Length() + sizeof(UInt32)))
        throw new std::runtime_error("Packet is missing data");
    Types::Reader reader(*this);
    UInt32 length = reader.ReadUInt32();
    reader.SkipBytes((int)length);
    return reader.ReadBytes(mac->Length());
}

bool Packet::CheckMAC(UInt32 sequenceNumber) const
{
    std::shared_ptr<IHMACAlgorithm> mac = _owner.GetIncomingHMAC();
    if (mac->Length() == 0)
        return true;
    Blob macPacket;
    Types::Writer macWriter(macPacket);
    macWriter.Write(sequenceNumber);
    macPacket.Append(Value(), Length() - mac->Length());
    return MAC().Compare(mac->Generate(macPacket));
}

Transport::Transport(Maths::IRandomSource& source)
:random(source)
{
    mode = Client;
    
    encryptionToClient = std::make_shared<NoEncryption>();
    encryptionToServer = encryptionToClient;
    
    macToClient = std::make_shared<NoHmac>();
    macToServer = macToClient;

    kexHandler = std::make_shared<Internal::KexHandler>(*this, mode);
}

void Transport::RegisterForPackets(IMessageHandler *handler, const Byte *number, int numberLength)
{
    UnregisterForPackets(number, numberLength);
    for (int i = 0; i < numberLength; i++)
        _packeters[number[i]] = handler;
}

void Transport::UnregisterForPackets(const Byte *number, int numberLength)
{
    for (int i = 0; i < numberLength; i++)
        _packeters[number[i]] = nullptr;
}

void Transport::ResetAlgorithms(bool local)
{
    if (local == (mode == Server)) {
        encryptionToClient = configuration.encryptionAlgorithms_serverToClient.at(*kexHandler->selectedEncryptionToServer)->Create(*this, Client);
        macToClient = configuration.macAlgorithms_serverToClient.at(*kexHandler->selectedMACToServer)->Create(*this, Client);
        _localKeyCounter++;
    } else {
        encryptionToServer = configuration.encryptionAlgorithms_clientToServer.at(*kexHandler->selectedEncryptionToClient)->Create(*this, Server);
        macToServer = configuration.macAlgorithms_clientToServer.at(*kexHandler->selectedMACToClient)->Create(*this, Server);
        _remoteKeyCounter++;
    }
    if (_localKeyCounter == _remoteKeyCounter)
        KeysChanged();
}

void Transport::KeysChanged(void)
{
    // We don't need to do anything here - client can hook it to detect when it can start authentication
}

void Transport::Start(void)
{
    constexpr Byte crlf[] = {13, 10};
    local.Reset();
    remote.Reset();
    _toSkip = 0;
    
    inputBuffer.Reset();
    _handler = std::make_shared<Internal::Initialiser>(*this);

    Types::Blob sending;
    // Transmit hello message lines
    if (local.message.size()) {
        for (const std::string& line : local.message) {
            sending.Append((Byte*)line.c_str(), (int)line.size());
            sending.Append(crlf, (int)sizeof(crlf));
            TestPrint('C', line);
        }
    }
    // Transmit SSH start
    local.version = std::string(Internal::ssh_ident, (int)strlen(Internal::ssh_ident));
    sending.Append((Byte*)local.version.c_str(), (int)local.version.size());
    sending.Append(crlf, (int)sizeof(crlf));
    TestPrint('C', local.version);
    // Send whole blob
    _delegate->Send(sending.Value(), sending.Length());
}

void Transport::SetDelegate(IDelegate *delegate)
{
    _delegate = delegate;
}

void Transport::Received(const void *data, UInt32 length)
{
    int previousLength = inputBuffer.Length();
    inputBuffer.Append((Byte*)data, (int)length);
    std::shared_ptr<Internal::Handler> lastHandler;
    do {
        lastHandler = _handler;
        _handler->HandleMoreData(previousLength);
        previousLength = 0;
    } while ((lastHandler != _handler) && inputBuffer.Length());
}

void Transport::InitialiseSSH(std::string remoteVersion, const std::vector<std::string>& message)
{
    remote.Reset();
    remote.version = remoteVersion;
    remote.message = message;
    // Switch to binary mode - initially unencrypted
    _handler = std::make_shared<Internal::BlockReceiver>(*this);
}

void Transport::HandlePacket(Packet block)
{
    if (_toSkip) {
        _toSkip--;
        return;
    }
    if (!block.CheckMAC(_remoteSeqCounter)) {
        Panic(PanicReason::InvalidMessage);    // TODO: Correct error
        return;
    }
    Types::Blob packet = block.Payload();
    Types::Reader reader(packet);
    Byte message = reader.ReadByte();
    IMessageHandler *handler = _packeters[message];
    DEBUG_LOG_TRANSFER(("S> message %s[%i]: %i bytes (%i total): %s\n", StringForSSHNumber(SSHMessages(message)).c_str(), message, packet.Length(), block.Length(), handler?"handled":"unclaimed"));
#ifdef DEBUG_LOG_CONTENT
    block.DebugDump();
#endif
    if (handler) {
        handler->HandlePayload(packet);
    } else {
        printf("Unimplemented message %s[%i]:\n", StringForSSHNumber(SSHMessages(message)).c_str(), message);
        packet.DebugDump();
        Types::Blob error;
        Types::Writer writer(error);
        writer.Write(UNIMPLEMENTED);
        writer.Write(_remoteSeqCounter);
        Send(error);
    }
    _remoteSeqCounter++;
}

void Transport::Send(Types::Blob payload)
{
    std::shared_ptr<IEncryptionAlgorithm> encrypter = GetOutgoingEncryption();
    int blockSize = encrypter->BlockSize();

    // TODO: compression (payload = Compress(payload))
    
    int minimumPadding = 4;    // Minimum 4 padding
    int minimumLength = /*packet_length*/ 4 + /*padding_length*/ 1 + payload.Length() + minimumPadding;
    minimumPadding += blockSize - (minimumLength % blockSize);
    int padding = minimumPadding;
    
    Types::Blob packet;
    Types::Writer writer(packet);
    writer.Write(UInt32(1 + payload.Length() + padding));
    writer.Write(Byte(padding));
    writer.Write(payload);
    for (int i = padding; i != 0;) {
        UInt32 aRandom = sessionID ? random.Random() : 0;
        if (i > 4) {
            writer.Write(UInt32(aRandom));
            i -= 4;
        } else if (i > 2) {
            writer.Write(Byte(aRandom));
            writer.Write(Byte(aRandom >> 8));
            i -= 2;
        } else {
            writer.Write(Byte(aRandom));
            i--;
        }
    }

    DEBUG_LOG_TRANSFER(("C> message %s[%i]: %i bytes (%i total)\n",
        StringForSSHNumber(SSHMessages(payload.Value()[0])).c_str(), payload.Value()[0],
        payload.Length(), packet.Length() + GetOutgoingHMAC()->Length()));
#ifdef DEBUG_LOG_CONTENT
    payload.DebugDump();
#endif
    
    // Encrypt the packet (a block at a time, as per the encryption algorithm) and transmit it
    for (int i = 0; i < packet.Length(); i += blockSize) {
        Types::Blob result = encrypter->Encrypt(Types::Blob(packet.Value() + i, blockSize));
        _delegate->Send(result.Value(), result.Length());
    }

    // Generate the MAC
    Types::Blob macPacket;
    Types::Writer macWriter(macPacket);
    macWriter.Write(_localSeqCounter);
    macWriter.Write(packet);
    Types::Blob macData = GetOutgoingHMAC()->Generate(macPacket);
    _delegate->Send(macData.Value(), macData.Length());

    _localSeqCounter++;
}

void Transport::Panic(PanicReason r)
{
    _delegate->Failed(r);
}

void Transport::SkipPacket(void)
{
    _toSkip++;
}

KeyExchanger::KeyExchanger(Transport& owner, Mode mode, const Hash::AType &hash)
:_owner(owner), _mode(mode), _hash(hash)
{
}

static Types::Blob MakeSameKey(const Hash::AType& hash, Maths::BigNumber K, Types::Blob H, Byte c, Types::Blob sessionID)
{
    Types::Blob blob;
    Types::Writer writer(blob);
    writer.Write(K);
    blob.Append((Byte*)H.Value(), H.Length());
    writer.Write(c);
    blob.Append((Byte*)sessionID.Value(), sessionID.Length());
    return *hash.Compute(blob);
}

void KeyExchanger::GenerateKeys(void)
{
    // Compute the new keys
    initialisationVectorC2S = MakeSameKey(_hash, key, exchangeHash, 'A', *_owner.sessionID);
    initialisationVectorS2C = MakeSameKey(_hash, key, exchangeHash, 'B', *_owner.sessionID);
    encryptionKeyC2S = MakeSameKey(_hash, key, exchangeHash, 'C', *_owner.sessionID);
    encryptionKeyS2C = MakeSameKey(_hash, key, exchangeHash, 'D', *_owner.sessionID);
    integrityKeyC2S = MakeSameKey(_hash, key, exchangeHash, 'E', *_owner.sessionID);
    integrityKeyS2C = MakeSameKey(_hash, key, exchangeHash, 'F', *_owner.sessionID);
    
#ifdef DEBUG_KEX
    printf("*** Generating keys ***\n");
    printf("A:\n"); initialisationVectorC2S.DebugDump();
    printf("B:\n"); initialisationVectorS2C.DebugDump();
    printf("C:\n"); encryptionKeyC2S.DebugDump();
    printf("D:\n"); encryptionKeyS2C.DebugDump();
    printf("E:\n"); integrityKeyC2S.DebugDump();
    printf("F:\n"); integrityKeyS2C.DebugDump();
#endif
    
    // Now we have keys, switch!
    Types::Blob message;
    Types::Writer writer(message);
    writer.Write(NEWKEYS);
    _owner.Send(message);

    // After that message is sent, all outgoing messages should be using the new algorithms, so switch now
    _owner.ResetAlgorithms(true);
    _owner.KeysChanged();  // TODO: make this only happen when ResetAlgorithms(true) and (false) has been called
}

Types::Blob KeyExchanger::ExtendKey(Types::Blob baseKey, UInt32 requiredLength)
{
    // Check K1 (which we already made, and is the input)
    if (requiredLength == baseKey.Length())
        return baseKey;
    
    // Shrink instead?
    if (requiredLength < baseKey.Length())
        return Types::Blob(baseKey.Value(), requiredLength);
    
    // Construct K || H || K1 (which is K2)
    Types::Blob extra;
    Types::Writer writer(extra);
    writer.Write(key);  // K
    writer.Write(exchangeHash);  // H
    writer.Write(baseKey);  // K1

    Types::Blob result;
    Types::Writer resultWriter(result);
    resultWriter.Write(baseKey);    // K1
    do {
        Types::Blob Kn = *_hash.Compute(extra);
        resultWriter.Write(Kn);
        writer.Write(Kn);
    } while (result.Length() < requiredLength);
    
    return result;
}

} // namespace minissh::Transport
