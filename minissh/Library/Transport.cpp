//
//  Transport.cpp
//  minissh
//
//  Created by Colin David Munro on 10/01/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
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
static void TestPrint(char c, sshString *line)
{
    fprintf(stdout, "%c> ", c);
    const char *str = line->Value();
    int len = line->Length();
    while (len) {
        fputc(*str, stdout);
        str++;
        len--;
    }
    fprintf(stdout, "\n");
}
#else
#define TestPrint(x, y)
#endif

namespace sshTransport_Internal {
    TransportInfo::TransportInfo()
    {
        version = NULL;
        message = NULL;
    }
    
    TransportInfo::~TransportInfo()
    {
        Reset();
    }
    
    void TransportInfo::Reset(void)
    {
        if (version) {
            version->Release();
            version = NULL;
        }
        if (message) {
            message->Release();
            message = NULL;
        }
    }
    
    class Handler : public sshObject
    {
    public:
        Handler(sshTransport *owner)
        {
            _owner = owner;
        }
    
        virtual void HandleMoreData(UInt32 previousLength) = 0;
        
    protected:
        sshTransport *_owner;
    };
    
    const char crlf[] = {13, 10, 0};
    const char* ssh = "SSH-";
    const char* ssh_ident = "SSH-2.0-miceSSH_1.0";

    static int MatchCharacters(const Byte *buffer, int bufferLength, const char *match, int matchLength)
    {
        int index = 0;
        int found = -1;
        int matched = 0;
        while (index < bufferLength) {
            if (buffer[index] == match[matched]) {
                if (matched == 0)
                    found = index;
                matched++;
                if (matched == matchLength)
                    return found;
            } else {
                matched = 0;
            }
            index++;
        }
        return -1;
    }
    
    static bool MatchStringStart(const sshString *first, const char *second, int secondLength)
    {
        const char *bytes = first->Value();
        int bytesLength = first->Length();
        if (bytesLength < secondLength)
            return false;
        for (int i = 0; i < secondLength; i++) {
            if (bytes[i] != second[i])
                return false;
        }
        return true;
    }
    
    static sshString* FindLine(sshBlob *blob)
    {
        // Get raw buffer
        const Byte *bytes = blob->Value();
        int length = blob->Length();
        // Find CR-LF
        int location = MatchCharacters(bytes, length, crlf, (int)strlen(crlf));
        if (location == -1)
            return NULL;
        // Make a string
        sshString *result = NULL;
        if (location != 0) {
            result = new sshString();
            result->Append((char*)bytes, location);
        }
        // Remove used data
        blob->Strip(0, location + (int)strlen(crlf));
        // Done
        return result;
    }
    
    class Initialiser : public Handler
    {
    public:
        // Read in strings until we get the SSH initialisation string
        
        Initialiser(sshTransport *owner)
        :Handler(owner)
        {
            _message = new sshNameList();
        }
        
        void HandleMoreData(UInt32 previousLength)
        {
            while (true) {
                sshString *line = FindLine(_owner->inputBuffer);
                if (line == NULL)
                    return;
                TestPrint('S', line);
                if (MatchStringStart(line, ssh, (int)strlen(ssh))) {
                    _owner->InitialiseSSH(line, _message->Count() ? _message : NULL);
                    return;
                } else {
                    _message->Add(line);
                }
                line->Release();
            }
        }
        
    protected:
        ~Initialiser()
        {
            _message->Release();
        }
        
    private:
        sshNameList *_message;
    };
    
    class BlockReceiver : public Handler
    {
    public:
        // Read in blocks of a specific size
        
        BlockReceiver(sshTransport *owner)
        :Handler(owner)
        {
            _packet = NULL;
        }
        
        void HandleMoreData(UInt32 previousLength)
        {
            int blockSize = ((_owner->mode == Server) ? _owner->encryptionToServer : _owner->encryptionToClient)->BlockSize();
            int amount;
            while (_owner->inputBuffer->Length() >= (amount = NextRead(blockSize))) {
                if (!_packet)
                    _packet = new sshPacket(_owner);
                _packet->Append(_owner->inputBuffer->Value(), amount);
                _owner->inputBuffer->Strip(0, amount);
                if (_packet->Satisfied()) {
                    _owner->HandlePacket(_packet);
                    _packet->Release();
                    _packet = NULL;
                }
            }
        }
        
    private:
        sshPacket *_packet;
        
        UInt32 NextRead(UInt32 blockSize)
        {
            if (!_packet)
                return blockSize;
            UInt32 amount = _packet->Requires();
            if (amount > blockSize)
                amount = blockSize;
            return amount;
        }
    };
    
    static sshString* CheckGuess(sshNameList *client, sshNameList *server)
    {
        sshString *clientGuess = client->ItemAt(0);
        if (clientGuess->IsEqual(server->ItemAt(0)))
            return clientGuess;
        return NULL;
    }
    
    static sshString* FindMatch(sshNameList *client, sshNameList *server)
    {
        for (int i = 0; i < client->Count(); i++) {
            sshString *name = client->ItemAt(i);
            for (int j = 0; j < server->Count(); j++) {
                if (name->IsEqual(server->ItemAt(j)))
                    return name;
            }
        }
        return NULL;
    }
    
    static sshString* FindMatch(TransportMode mode, sshNameList *remoteList, sshDictionary *localList)
    {
        sshString *result = FindMatch((mode == Server) ? remoteList : localList->AllKeys(), (mode == Server) ? localList->AllKeys() : remoteList);
        if (result)
            result->AddRef();
        return result;
    }
    
    class KexHandler : public sshMessageHandler
    {
    private:
        sshTransport *_owner;
        TransportMode _mode;
        bool _expectingInit;
        sshKeyExchanger *_activeExchanger;
        
        void SendKex(void)
        {
            if (_expectingInit)
                return;
            sshBlob *output = new sshBlob();
            sshWriter writer(output);
            writer.Write(Byte(SSH_MSG_KEXINIT));
            // Cookie
            for (int i = 0; i < 4; i++)
                writer.Write(UInt32(_owner->random->Random()));
            // All the lists
            writer.Write(_owner->configuration->supportedKeyExchanges->AllKeys());
            writer.Write(_owner->configuration->serverHostKeyAlgorithms->AllKeys());
            writer.Write(_owner->configuration->encryptionAlgorithms_clientToServer->AllKeys());
            writer.Write(_owner->configuration->encryptionAlgorithms_serverToClient->AllKeys());
            writer.Write(_owner->configuration->macAlgorithms_clientToServer->AllKeys());
            writer.Write(_owner->configuration->macAlgorithms_serverToClient->AllKeys());
            writer.Write(_owner->configuration->compressionAlgorithms_clientToServer->AllKeys());
            writer.Write(_owner->configuration->compressionAlgorithms_serverToClient->AllKeys());
            writer.Write(_owner->configuration->languages_clientToServer->AllKeys());
            writer.Write(_owner->configuration->languages_serverToClient->AllKeys());
            writer.Write(bool(false));  // TODO: guesses
            writer.Write(UInt32(0));    // Reserved
            
            _owner->local.kexPayload = output;
            
            _expectingInit = true;
            _owner->Send(output);
        }
    public:
        KexHandler(sshTransport *owner, TransportMode mode)
        {
            _expectingInit = false;
            
            const Byte messages[] = {SSH_MSG_KEXINIT, SSH_MSG_NEWKEYS};
            _owner = owner;
            _owner->RegisterForPackets(this, messages, sizeof(messages) / sizeof(messages[0]));
            _mode = mode;

            selectedEncryptionToServer = NULL;
            selectedEncryptionToClient = NULL;
            selectedMACToServer = NULL;
            selectedMACToClient = NULL;
            selectedCompressionToServer = NULL;
            selectedCompressionToClient = NULL;
        }
        
        void HandlePayload(sshBlob *data)
        {
            sshReader reader(data);
            
            switch (reader.ReadByte()) {
                case SSH_MSG_KEXINIT:
                {
                    // Store the remote's payload
                    if (_owner->remote.kexPayload)
                        _owner->remote.kexPayload->Release();
                    _owner->remote.kexPayload = data;
                    _owner->remote.kexPayload->AddRef();
                    // Get values
                    reader.SkipBytes(16);   // Cookie
                    sshNameList *kexAlgorithms = reader.ReadNameList();  // Kex Algorithms
                    sshNameList *hostKeyAlgorithms = reader.ReadNameList();  // Server Host Key Algorithms
                    sshNameList *encryptionAlgorithms_C2S = reader.ReadNameList();  // encryption (C2S)
                    sshNameList *encryptionAlgorithms_S2C = reader.ReadNameList();  // encryption (S2C)
                    sshNameList *mac_C2S = reader.ReadNameList();  // MAC (C2S)
                    sshNameList *mac_S2C = reader.ReadNameList();  // MAC (S2C)
                    sshNameList *compression_C2S = reader.ReadNameList();  // Compression (C2S)
                    sshNameList *compression_S2C = reader.ReadNameList();  // Compression (S2C)
                    sshNameList *language_C2S = reader.ReadNameList();  // Language (C2S)
                    sshNameList *language_S2C = reader.ReadNameList();  // Language (S2C)
                    bool kex_follows = reader.ReadBoolean();   // First KEX packet follows
                    // Reply, if necessary
                    if (!_expectingInit)
                        SendKex();
                    // Do something about it
                    sshString *kexAlgo = NULL;
                    if (kex_follows) {
                        kexAlgo = CheckGuess(kexAlgorithms, _owner->configuration->supportedKeyExchanges->AllKeys());
                        if (!kexAlgo)
                            _owner->SkipPacket();
                    }
                    if (!kexAlgo)
                        kexAlgo = FindMatch(_mode, kexAlgorithms, _owner->configuration->supportedKeyExchanges);
                    if (!kexAlgo) {
                        _owner->Panic(sshTransport::prNoMatchingAlgorithm);
                        return;
                    }
                    // Find the other algorithms (less complicated)
                    if (selectedEncryptionToClient)
                        selectedEncryptionToClient->Release();
                    selectedEncryptionToClient = FindMatch(_mode, encryptionAlgorithms_S2C, _owner->configuration->encryptionAlgorithms_serverToClient);
                    if (selectedEncryptionToServer)
                        selectedEncryptionToServer->Release();
                    selectedEncryptionToServer = FindMatch(_mode, encryptionAlgorithms_C2S, _owner->configuration->encryptionAlgorithms_clientToServer);
                    if (selectedMACToClient)
                        selectedMACToClient->Release();
                    selectedMACToClient = FindMatch(_mode, mac_S2C, _owner->configuration->macAlgorithms_serverToClient);
                    if (selectedMACToServer)
                        selectedMACToServer->Release();
                    selectedMACToServer = FindMatch(_mode, mac_C2S, _owner->configuration->macAlgorithms_clientToServer);
                    if (selectedCompressionToClient)
                        selectedCompressionToClient->Release();
                    selectedCompressionToClient = FindMatch(_mode, compression_S2C, _owner->configuration->compressionAlgorithms_serverToClient);
                    if (selectedCompressionToServer)
                        selectedCompressionToServer->Release();
                    selectedCompressionToServer = FindMatch(_mode, compression_C2S, _owner->configuration->compressionAlgorithms_clientToServer);
                    if (!(selectedCompressionToClient && selectedCompressionToServer && selectedEncryptionToClient && selectedEncryptionToServer && selectedMACToClient && selectedMACToServer)) {
                        _owner->Panic(sshTransport::prNoMatchingAlgorithm);
                        return;
                    }
                    // Select host key algorithm (TODO: this should be done in conjunction with kex)
                    sshString *hostKeyAlgo = FindMatch(_mode, hostKeyAlgorithms, _owner->configuration->serverHostKeyAlgorithms);
                    if (!hostKeyAlgo) {
                        _owner->Panic(sshTransport::prNoMatchingAlgorithm);
                        return;
                    }
                    // Start
                    _owner->hostKeyAlgorithm = (sshHostKeyAlgorithm*)((sshConfiguration::Factory*)_owner->configuration->serverHostKeyAlgorithms->ObjectFor(hostKeyAlgo))->Instantiate(_owner, _mode);
                    _activeExchanger= (sshKeyExchanger*)((sshConfiguration::Factory*)_owner->configuration->supportedKeyExchanges->ObjectFor(kexAlgo))->Instantiate(_owner, _mode);
                    _owner->keyExchanger = _activeExchanger;
                    _activeExchanger->Start();
                }
                    break;
                case SSH_MSG_NEWKEYS:
                    _expectingInit = false;
                    // New keys ready to go, all incoming messages should now be using the new algorithms
                    _owner->ResetAlgorithms(false);
                    break;
            }
        }
        
        sshString *selectedEncryptionToServer;
        sshString *selectedEncryptionToClient;
        sshString *selectedMACToServer;
        sshString *selectedMACToClient;
        sshString *selectedCompressionToServer;
        sshString *selectedCompressionToClient;
        
    protected:
        ~KexHandler()
        {
            const Byte messages[] = {SSH_MSG_KEXINIT, SSH_MSG_NEWKEYS};
            _owner->UnregisterForPackets(messages, sizeof(messages) / sizeof(messages[0]));
            if (selectedEncryptionToServer != NULL)
                selectedEncryptionToServer->Release();
            if (selectedEncryptionToClient != NULL)
                selectedEncryptionToClient->Release();
            if (selectedMACToServer != NULL)
                selectedMACToServer->Release();
            if (selectedMACToClient != NULL)
                selectedMACToClient->Release();
            if (selectedCompressionToServer != NULL)
                selectedCompressionToServer->Release();
            if (selectedCompressionToClient != NULL)
                selectedCompressionToClient->Release();
        }
    };
    
    // This class allows the transport to start up in an unencrypted mode without treating it as a special case
    class NoEncryption : public sshEncryptionAlgorithm
    {
    public:
        NoEncryption()
        {
        }
        
        int BlockSize(void)
        {
            return 8;
        }
        
        sshBlob* Encrypt(sshBlob *data)
        {
            return data;
        }
        
        sshBlob* Decrypt(sshBlob *data)
        {
            return data;
        }
    };
    
    class NoHmac : public sshHMACAlgorithm
    {
    public:
        NoHmac()
        {
        }
        
        sshBlob* Generate(sshBlob *packet)
        {
            sshBlob *result = new sshBlob();
            result->Autorelease();
            return result;
        }
        
        int Length(void)
        {
            return 0;
        }
    };
}

sshConfiguration::sshConfiguration()
{
    supportedKeyExchanges = new sshDictionary();
    serverHostKeyAlgorithms = new sshDictionary();
    encryptionAlgorithms_clientToServer = new sshDictionary();
    encryptionAlgorithms_serverToClient = new sshDictionary();
    macAlgorithms_clientToServer = new sshDictionary();
    macAlgorithms_serverToClient = new sshDictionary();
    compressionAlgorithms_clientToServer = new sshDictionary();
    compressionAlgorithms_serverToClient = new sshDictionary();
    languages_clientToServer = new sshDictionary();
    languages_serverToClient = new sshDictionary();
}

sshConfiguration::~sshConfiguration()
{
    supportedKeyExchanges->Release();
    serverHostKeyAlgorithms->Release();
    encryptionAlgorithms_clientToServer->Release();
    encryptionAlgorithms_serverToClient->Release();
    macAlgorithms_clientToServer->Release();
    macAlgorithms_serverToClient->Release();
    compressionAlgorithms_clientToServer->Release();
    compressionAlgorithms_serverToClient->Release();
    languages_clientToServer->Release();
    languages_serverToClient->Release();
}

sshPacket::sshPacket(sshTransport *owner)
{
    _owner = owner;
    _decodedBlocks = 0;
    _requiredBlocks = 0;
}

void sshPacket::Append(const Byte *bytes, int length)
{
    sshBlob::Append(bytes, length);
    // Hacky
    if (_requiredBlocks && (_decodedBlocks >= _requiredBlocks))
        return;
    sshEncryptionAlgorithm *decrypter = (_owner->mode == Client) ? _owner->encryptionToClient : _owner->encryptionToServer;
    int blockSize = decrypter->BlockSize();
    sshBlob *chunk = new sshBlob();
    int offset = _decodedBlocks * blockSize;
    while ((!_requiredBlocks || (_decodedBlocks < _requiredBlocks)) && ((offset + blockSize) <= Length())) {
        chunk->Reset();
        chunk->Append(Value() + offset, blockSize);
        sshBlob *decoded = decrypter->Decrypt(chunk);
        memcpy((void*)(Value() + offset), decoded->Value(), blockSize);
        _decodedBlocks++;
        if (!_requiredBlocks)
            _requiredBlocks = (PacketLength() + sizeof(UInt32)) / blockSize;
        offset += blockSize;
    }
    chunk->Release();
}

bool sshPacket::Satisfied(void)
{
    sshEncryptionAlgorithm *decrypter = (_owner->mode == Client) ? _owner->encryptionToClient : _owner->encryptionToServer;
    sshHMACAlgorithm *mac = (_owner->mode == Client) ? _owner->macToClient : _owner->macToServer;
    if (Length() < decrypter->BlockSize())
        return false;
    return Length() == PacketLength() + sizeof(UInt32) + mac->Length();
}

UInt32 sshPacket::Requires(void)
{
    sshEncryptionAlgorithm *decrypter = (_owner->mode == Client) ? _owner->encryptionToClient : _owner->encryptionToServer;
    UInt32 blockSize = decrypter->BlockSize();
    if (Length() < blockSize)
        return blockSize;
    sshHMACAlgorithm *mac = (_owner->mode == Client) ? _owner->macToClient : _owner->macToServer;
    return PacketLength() + sizeof(UInt32) + mac->Length() - Length();
}

UInt32 sshPacket::PacketLength(void) const
{
    sshReader reader(this);
    return reader.ReadUInt32();
}

UInt32 sshPacket::PaddingLength(void) const
{
    sshReader reader(this);
    reader.ReadUInt32();    // Skip packet length
    return reader.ReadByte();
}

sshBlob* sshPacket::Payload(void) const
{
    sshEncryptionAlgorithm *decrypter = (_owner->mode == Client) ? _owner->encryptionToClient : _owner->encryptionToServer;
    if (Length() < decrypter->BlockSize())
        return NULL;
    sshReader reader(this);
    UInt32 length = reader.ReadUInt32();
    length -= reader.ReadByte();
    length--;
    if (Length() < (length + sizeof(UInt32)))
        return NULL;
    return reader.ReadBytes((int)length);
}

sshBlob* sshPacket::Padding(void) const
{
    if (Length() < (PacketLength() + sizeof(UInt32)))
        return NULL;
    sshReader reader(this);
    UInt32 length = reader.ReadUInt32();
    length -= reader.ReadByte();
    length--;
    reader.SkipBytes((int)length);
    return reader.ReadBytes((int)length);
}

sshBlob* sshPacket::MAC(void) const
{
    sshHMACAlgorithm *mac = (_owner->mode == Client) ? _owner->macToClient : _owner->macToServer;
    if (Length() < (PacketLength() + mac->Length() + sizeof(UInt32)))
        return NULL;
    sshReader reader(this);
    UInt32 length = reader.ReadUInt32();
    reader.SkipBytes((int)length);
    return reader.ReadBytes(mac->Length());
}

bool sshPacket::CheckMAC(UInt32 sequenceNumber) const
{
    sshHMACAlgorithm *mac = (_owner->mode == Client) ? _owner->macToClient : _owner->macToServer;
    if (mac->Length() == 0)
        return true;
    sshBlob *current = MAC();
    sshBlob *macPacket = new sshBlob();
    sshWriter macWriter(macPacket);
    macWriter.Write(sequenceNumber);
    macPacket->Append(Value(), Length() - mac->Length());
    sshBlob *computed = mac->Generate(macPacket);
    macPacket->Release();
    return current->Compare(computed);
}

sshTransport::sshTransport()
{
    mode = Client;
    
    inputBuffer = new sshBlob();
    configuration = new sshConfiguration();
    _handler = NULL;
    for (int i = 0; i < 256; i++)
        _packeters[i] = NULL;
    sessionID = NULL;
    
    encryptionToClient = new sshTransport_Internal::NoEncryption();
    encryptionToServer = encryptionToClient;
    encryptionToClient->AddRef();
    
    macToClient = new sshTransport_Internal::NoHmac();
    macToServer = macToClient;
    macToServer->AddRef();
    
    _localKeyCounter = _remoteKeyCounter = 0;

    kexHandler = new sshTransport_Internal::KexHandler(this, mode);
}

sshTransport::~sshTransport()
{
    kexHandler->Release();
    encryptionToClient->Release();
    encryptionToServer->Release();
    macToClient->Release();
    macToServer->Release();
    if (_handler)
        _handler->Release();
    if (_delegate)
        _delegate->Release();
    inputBuffer->Release();
    for (int i = 0; i < 256; i++) {
        if (_packeters[i])
            _packeters[i]->Release();
    }
    if (configuration)
        configuration->Release();
}

void sshTransport::RegisterForPackets(sshMessageHandler *handler, const Byte *number, int numberLength)
{
    UnregisterForPackets(number, numberLength);
    for (int i = 0; i < numberLength; i++) {
        _packeters[number[i]] = handler;
        handler->AddRef();
    }
}

void sshTransport::UnregisterForPackets(const Byte *number, int numberLength)
{
    for (int i = 0; i < numberLength; i++) {
        if (_packeters[number[i]]) {
            _packeters[number[i]]->Release();
            _packeters[number[i]] = NULL;
        }
    }
}

void sshTransport::ResetAlgorithms(bool local)
{
    if (local == (mode == Server)) {
        encryptionToClient->Release();
        macToClient->Release();
        
        encryptionToClient = (sshEncryptionAlgorithm*)((sshConfiguration::Factory*)configuration->encryptionAlgorithms_serverToClient->ObjectFor(kexHandler->selectedEncryptionToServer))->Instantiate(this, Client);
        macToClient = (sshHMACAlgorithm*)((sshConfiguration::Factory*)configuration->macAlgorithms_serverToClient->ObjectFor(kexHandler->selectedMACToServer))->Instantiate(this, Client);
        
        _localKeyCounter++;
    } else {
        encryptionToServer->Release();
        macToServer->Release();
        
        encryptionToServer = (sshEncryptionAlgorithm*)((sshConfiguration::Factory*)configuration->encryptionAlgorithms_clientToServer->ObjectFor(kexHandler->selectedEncryptionToClient))->Instantiate(this, Server);
        macToServer = (sshHMACAlgorithm*)((sshConfiguration::Factory*)configuration->macAlgorithms_clientToServer->ObjectFor(kexHandler->selectedMACToClient))->Instantiate(this, Server);
        
        _remoteKeyCounter++;
    }
    if (_localKeyCounter == _remoteKeyCounter)
        KeysChanged();
}

void sshTransport::KeysChanged(void)
{
    // We don't need to do anything here - client can hook it to detect when it can start authentication
}

void sshTransport::Start(void)
{
    local.Reset();
    remote.Reset();
    _toSkip = 0;
    
    inputBuffer->Reset();
    SetHandler(new sshTransport_Internal::Initialiser(this));

    sshBlob *sending = new sshBlob();
    // Transmit hello message lines
    if (local.message) {
        for (int i = 0, j = local.message->Count(); i < j; i++) {
            sshString *string = local.message->ItemAt(i);
            sending->Append((Byte*)string->Value(), string->Length());
            sending->Append((Byte*)sshTransport_Internal::crlf, (int)strlen(sshTransport_Internal::crlf));
            TestPrint('C', string);
        }
    }
    // Transmit SSH start
    local.version = new sshString();
    local.version->Append(sshTransport_Internal::ssh_ident, (int)strlen(sshTransport_Internal::ssh_ident));
    sending->Append((Byte*)local.version->Value(), local.version->Length());
    sending->Append((Byte*)sshTransport_Internal::crlf, (int)strlen(sshTransport_Internal::crlf));
    TestPrint('C', local.version);
    // Send whole blob
    _delegate->Send(sending->Value(), sending->Length());
    sending->Release();
}

void sshTransport::SetHandler(sshTransport_Internal::Handler *handler)
{
    if (_handler)
        _handler->Release();
    _handler = handler;
}

void sshTransport::SetDelegate(Delegate *delegate)
{
    if (_delegate)
        _delegate->Release();
    _delegate = delegate;
    if (_delegate)
        _delegate->AddRef();
}

void sshTransport::Received(const void *data, UInt32 length)
{
    int previousLength = inputBuffer->Length();
    inputBuffer->Append((Byte*)data, (int)length);
    sshTransport_Internal::Handler *lastHandler;
    do {
        lastHandler = _handler;
        _handler->HandleMoreData(previousLength);
        previousLength = 0;
    } while ((lastHandler != _handler) && inputBuffer->Length());
}

void sshTransport::InitialiseSSH(sshString *remoteVersion, sshNameList *message)
{
    remote.Reset();
    remote.version = remoteVersion;
    remote.version->AddRef();
    if (message) {
        remote.message = message;
        remote.message->AddRef();
    }
    // Switch to binary mode - initially unencrypted
    SetHandler(new sshTransport_Internal::BlockReceiver(this));
}

void sshTransport::HandlePacket(sshPacket *block)
{
    if (_toSkip) {
        _toSkip--;
        return;
    }
    if (!block->CheckMAC(_remoteSeqCounter)) {
        Panic(prInvalidMessage);    // TODO: Correct error
        return;
    }
    sshBlob *packet = block->Payload();
    sshReader reader(packet);
    Byte message = reader.ReadByte();
    sshMessageHandler *handler = _packeters[message];
    DEBUG_LOG_TRANSFER(("S> message %i: %i bytes (%i total): %s\n", message, packet->Length(), block->Length(), handler?"handled":"unclaimed"));
    if (handler) {
        handler->HandlePayload(packet);
    } else {
        printf("Unimplemented message %i:\n", message);
        packet->DebugDump();
        sshBlob *error = new sshBlob();
        sshWriter writer(error);
        writer.Write(Byte(SSH_MSG_UNIMPLEMENTED));
        writer.Write(_remoteSeqCounter);
        Send(error);
        error->Release();
    }
    _remoteSeqCounter++;
}

void sshTransport::Send(sshBlob *payload)
{
    sshEncryptionAlgorithm *encrypter = (mode == Client) ? encryptionToServer : encryptionToClient;
    int blockSize = encrypter->BlockSize();

    // TODO: compression (payload = Compress(payload))
    
    int minimumPadding = 4;    // Minimum 4 padding
    int minimumLength = /*packet_length*/ 4 + /*padding_length*/ 1 + payload->Length() + minimumPadding;
    minimumPadding += blockSize - (minimumLength % blockSize);
    int paddingScale = (255 - minimumPadding) / blockSize;
//    int padding = minimumPadding + ((random->Random() % paddingScale) * blockSize);
    int padding = minimumPadding;
    
    sshBlob *packet = new sshBlob();
    sshWriter writer(packet);
    writer.Write(UInt32(1 + payload->Length() + padding));
    writer.Write(Byte(padding));
    writer.Write(payload);
    for (int i = padding; i != 0;) {
        UInt32 aRandom = sessionID ? random->Random() : 0;
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

    DEBUG_LOG_TRANSFER(("C> message %i: %i bytes (%i total)\n", payload->Value()[0], payload->Length(), packet->Length() + ((mode == Client) ? macToServer : macToClient)->Length()));
    
    // Encrypt the packet (a block at a time, as per the encryption algorithm) and transmit it
    sshBlob *chunk = new sshBlob();
    for (int i = 0; i < packet->Length(); i += blockSize) {
        chunk->Reset();
        chunk->Append(packet->Value() + i, blockSize);
        sshBlob *result = encrypter->Encrypt(chunk);
        _delegate->Send(result->Value(), result->Length());
    }
    chunk->Release();

    // Generate the MAC
    sshBlob *macPacket = new sshBlob();
    sshWriter macWriter(macPacket);
    macWriter.Write(_localSeqCounter);
    macWriter.Write(packet);
    packet->Release();
    sshBlob *macData = ((mode == Client) ? macToServer : macToClient)->Generate(macPacket);
    macPacket->Release();
    _delegate->Send(macData->Value(), macData->Length());

    _localSeqCounter++;
}

void sshTransport::Panic(PanicReason r)
{
    _delegate->Failed(r);
}

void sshTransport::SkipPacket(void)
{
    _toSkip++;
}

sshKeyExchanger::sshKeyExchanger(sshTransport *owner, TransportMode mode)
{
    _owner = owner;
    _mode = mode;
}

static sshBlob* MakeSameKey(HashType *hash, BigNumber K, sshString *H, Byte c, sshString *sessionID)
{
    sshBlob *blob = new sshBlob();
    sshWriter writer(blob);
    writer.Write(K);
    blob->Append((Byte*)H->Value(), H->Length());
    writer.Write(c);
    blob->Append((Byte*)sessionID->Value(), sessionID->Length());
    sshBlob *result = hash->Compute(blob);
    blob->Release();
    result->AddRef();   // For convenience of caller
    return result;
}

void sshKeyExchanger::GenerateKeys(void)
{
    // Compute the new keys
    initialisationVectorC2S = MakeSameKey(hash, key, exchangeHash, 'A', _owner->sessionID);
    initialisationVectorS2C = MakeSameKey(hash, key, exchangeHash, 'B', _owner->sessionID);
    encryptionKeyC2S = MakeSameKey(hash, key, exchangeHash, 'C', _owner->sessionID);
    encryptionKeyS2C = MakeSameKey(hash, key, exchangeHash, 'D', _owner->sessionID);
    integrityKeyC2S = MakeSameKey(hash, key, exchangeHash, 'E', _owner->sessionID);
    integrityKeyS2C = MakeSameKey(hash, key, exchangeHash, 'F', _owner->sessionID);
    
#ifdef DEBUG_KEX
    printf("*** Generating keys ***\n");
    printf("A:\n"); initialisationVectorC2S->DebugDump();
    printf("B:\n"); initialisationVectorS2C->DebugDump();
    printf("C:\n"); encryptionKeyC2S->DebugDump();
    printf("D:\n"); encryptionKeyS2C->DebugDump();
    printf("E:\n"); integrityKeyC2S->DebugDump();
    printf("F:\n"); integrityKeyS2C->DebugDump();
#endif
    
    // Now we have keys, switch!
    sshBlob *message = new sshBlob();
    sshWriter writer(message);
    writer.Write(Byte(SSH_MSG_NEWKEYS));
    _owner->Send(message);
    message->Release();

    // After that message is sent, all outgoing messages should be using the new algorithms, so switch now
    _owner->ResetAlgorithms(true);
    _owner->KeysChanged();  // TODO: make this only happen when ResetAlgorithms(true) and (false) has been called
}

sshBlob* sshKeyExchanger::ExtendKey(sshBlob *baseKey, UInt32 requiredLength)
{
    // Check K1 (which we already made, and is the input)
    if (requiredLength == baseKey->Length())
        return baseKey;
    
    // Shrink instead?
    if (requiredLength < baseKey->Length()) {
        sshBlob *result = new sshBlob();
        result->Append(baseKey->Value(), requiredLength);
        result->Autorelease();
        return result;
    }
    
    // Construct K || H || K1 (which is K2)
    sshBlob *extra = new sshBlob();
    sshWriter writer(extra);
    writer.Write(key);  // K
    writer.Write(exchangeHash);  // H
    writer.Write(baseKey);  // K1

    sshBlob *result = new sshBlob();
    sshWriter resultWriter(result);
    resultWriter.Write(baseKey);    // K1
    do {
        sshBlob *Kn = hash->Compute(extra);
        resultWriter.Write(Kn);
        writer.Write(Kn);
    } while (result->Length() < requiredLength);
    
    extra->Release();
    result->Autorelease();
    return result;
}
