//
//  Transport.h
//  minissh
//
//  Created by Colin David Munro on 10/01/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#pragma once

#include <map>
#include "Types.h"
#include "Hash.h"

namespace minissh::Maths {
class RandomSource;
} // namespace minissh::Maths

namespace minissh::Transport {

class Transport;
class HMACAlgorithm;

namespace Internal {
    class Handler;
    class KexHandler;
    
    class TransportInfo
    {
    public:
        TransportInfo();
        ~TransportInfo();
        void Reset(void);
        
        std::string version;
        std::vector<std::string> message;
        Types::Blob kexPayload;
    };
}

typedef enum {
    Server,
    Client,
} Mode;

class MessageHandler
{
public:
    virtual ~MessageHandler() = default;
    
    virtual void HandlePayload(Types::Blob data) = 0;
};

class KeyExchanger : public MessageHandler
{
public:
    KeyExchanger(Transport& owner, Mode mode, const Hash::Type& hash);
    virtual void Start(void) = 0;
    
    void GenerateKeys(void);
    Types::Blob ExtendKey(Types::Blob baseKey, UInt32 requiredLength);
    
    
    Maths::BigNumber key;
    Types::Blob exchangeHash;
    
    Types::Blob initialisationVectorC2S;
    Types::Blob initialisationVectorS2C;
    Types::Blob encryptionKeyC2S;
    Types::Blob encryptionKeyS2C;
    Types::Blob integrityKeyC2S;
    Types::Blob integrityKeyS2C;
protected:
    const Hash::Type &_hash;
    Transport &_owner;
    Mode _mode;
};

class HostKeyAlgorithm
{
public:
    virtual ~HostKeyAlgorithm() = default;
    
    // Confirm that a host key is acceptable (usually checking the key against a database in the local machine, or asking the user about it)
    virtual bool Confirm(Types::Blob hostKey) = 0;
    
    // Confirm the signature is valid
    virtual bool Verify(Types::Blob hostKey, Types::Blob signature, Types::Blob exchangeHash) = 0;
};

class EncryptionAlgorithm
{
public:
    virtual ~EncryptionAlgorithm() = default;
    
    virtual int BlockSize(void) = 0;
    
    virtual Types::Blob Encrypt(Types::Blob data) = 0;
    virtual Types::Blob Decrypt(Types::Blob data) = 0;
};

class HMACAlgorithm
{
public:
    virtual ~HMACAlgorithm() = default;
    
    virtual Types::Blob Generate(Types::Blob packet) = 0;
    virtual int Length(void) = 0;
};

class Compression
{
public:
    // TODO: Implement compression
};

class Language
{
public:
    // TODO: Implement languages
};

/**
 * Class to contain the basic configuration of the SSH transport (e.g. supporte algorithms)
 */
class Configuration
{
public:
    template<class Base> class Instantiator
    {
    public:
        virtual ~Instantiator() = default;
        virtual std::shared_ptr<Base> Create(Transport& owner, Mode mode) const = 0;
    };
    
    std::map<std::string, std::shared_ptr<Instantiator<KeyExchanger>>> supportedKeyExchanges;
    std::map<std::string, std::shared_ptr<Instantiator<HostKeyAlgorithm>>> serverHostKeyAlgorithms;
    std::map<std::string, std::shared_ptr<Instantiator<EncryptionAlgorithm>>> encryptionAlgorithms_clientToServer;
    std::map<std::string, std::shared_ptr<Instantiator<EncryptionAlgorithm>>> encryptionAlgorithms_serverToClient;
    std::map<std::string, std::shared_ptr<Instantiator<HMACAlgorithm>>> macAlgorithms_clientToServer;
    std::map<std::string, std::shared_ptr<Instantiator<HMACAlgorithm>>> macAlgorithms_serverToClient;
    std::map<std::string, std::shared_ptr<Instantiator<Compression>>> compressionAlgorithms_clientToServer;
    std::map<std::string, std::shared_ptr<Instantiator<Compression>>> compressionAlgorithms_serverToClient;
    std::map<std::string, std::shared_ptr<Instantiator<Language>>> languages_clientToServer;
    std::map<std::string, std::shared_ptr<Instantiator<Language>>> languages_serverToClient;
    
    template<class Class, class Base> class Instantiatable
    {
    private:
        class Factory : public Instantiator<Base>
        {
        public:
            std::shared_ptr<Base> Create(Transport& owner, Mode mode) const override
            {
                return std::make_shared<Class>(owner, mode);
            }
        };
    public:
        static void Add(std::map<std::string, std::shared_ptr<Instantiator<Base>>> &list)
        {
            list.insert(std::pair<std::string, std::shared_ptr<Instantiator<Base>>>(std::string(Class::Name), std::make_shared<Factory>()));
        }
    };
};
    
class NoneCompression : public Compression
{
public:
    static constexpr char Name[] = "none";
    class Factory : public Configuration::Instantiatable<NoneCompression, Compression>
    {
    };
    
    NoneCompression(Transport& owner, Mode mode)
    {
    }
};

class Packet : public Types::Blob
{
public:
    Packet(Transport& owner);
    
    void Append(const Byte *bytes, int length);
    
    bool Satisfied(void);   // True when the whole packet is in and decoded
    UInt32 Requires(void);
    
    UInt32 PacketLength(void) const;
    UInt32 PaddingLength(void) const;
    Types::Blob Payload(void) const;
    Types::Blob Padding(void) const;
    Types::Blob MAC(void) const;
    
    bool CheckMAC(UInt32 sequenceNumber) const;
    
private:
    Transport &_owner;
    int _decodedBlocks = 0;
    int _requiredBlocks = 0;
};

class Service
{
public:
    virtual bool EnableForAuthentication(void *data /* todo */) = 0;
};

class Transport
{
public:
    enum class PanicReason {
        OutOfRange,
        InvalidMessage,
        NoMatchingAlgorithm,
        BadHostKey,
        BadSignature,
    };
    static std::string StringForPanicReason(PanicReason reason);
    
    class Delegate
    {
    public:
        virtual void Send(const void *data, UInt32 length) = 0;
        virtual void Failed(PanicReason reason) = 0;
    };
    
    // Internal
    std::shared_ptr<Internal::KexHandler> kexHandler;
    Types::Blob inputBuffer;
    void InitialiseSSH(std::string remoteVersion, const std::vector<std::string>& message);
    void HandlePacket(Packet block);
    void ResetAlgorithms(bool local);
    virtual void KeysChanged(void);
    
    void Send(Types::Blob payload);
    void Panic(PanicReason r);
    void SkipPacket(void);
    
    void RegisterForPackets(MessageHandler* handler, const Byte* number, int numberLength);
    void UnregisterForPackets(const Byte* number, int numberLength);
    // TODO; disable/etc.

public:
    Transport(Maths::RandomSource& source);
    
    // Network interface
    void SetDelegate(Delegate* delegate);
    void Received(const void *data, UInt32 length);

    // Startup
    Internal::TransportInfo local, remote;
    std::shared_ptr<HostKeyAlgorithm> hostKeyAlgorithm;
    std::optional<Types::Blob> sessionID;
    std::shared_ptr<KeyExchanger> keyExchanger;
    
    // Running
    std::shared_ptr<EncryptionAlgorithm> encryptionToServer;
    std::shared_ptr<EncryptionAlgorithm> encryptionToClient;
    std::shared_ptr<HMACAlgorithm> macToServer;
    std::shared_ptr<HMACAlgorithm> macToClient;
    
    // Supported
    Mode mode;
    Configuration configuration;
    Maths::RandomSource &random;
    
    // Control
    void Start(void);
    
    // Utilities
    inline std::shared_ptr<EncryptionAlgorithm> GetIncomingEncryption(void)
    {
        return (mode == Client) ? encryptionToClient : encryptionToServer;
    }
    inline std::shared_ptr<EncryptionAlgorithm> GetOutgoingEncryption(void)
    {
        return (mode == Client) ? encryptionToServer : encryptionToClient;
    }
    inline std::shared_ptr<HMACAlgorithm> GetIncomingHMAC(void)
    {
        return (mode == Client) ? macToClient : macToServer;
    }
    inline std::shared_ptr<HMACAlgorithm> GetOutgoingHMAC(void)
    {
        return (mode == Client) ? macToServer : macToClient;
    }

private:
    Delegate *_delegate = nullptr;
    std::shared_ptr<Internal::Handler> _handler;
    MessageHandler *_packeters[256];
    int _toSkip;
    UInt32 _localSeqCounter, _remoteSeqCounter;
    UInt32 _localKeyCounter = 0;
    UInt32 _remoteKeyCounter = 0;
};

} // namespace minissh::Transport
