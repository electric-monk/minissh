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
#include "KeyFile.h"
#include "SshNumbers.h"

namespace minissh::Maths {
class IRandomSource;
} // namespace minissh::Maths

namespace minissh::Transport {

class Transport;
class IHMACAlgorithm;

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

/**
 * Mode for transport. The transport behaviour is the same whether it's in the server or client, but it needs to know
 * which encryption, HMAC and other methods it's using depending on which side it's on.
 */
typedef enum {
    Server,
    Client,
} Mode;

/**
 * Interface class for receiving some sort of message from the remote end.
 */
class IMessageHandler
{
public:
    virtual ~IMessageHandler() = default;
    
    virtual void HandlePayload(Types::Blob data) = 0;
};

/**
 * Class to handle initial key exchange, before enabling encryption.
 */
class KeyExchanger : public IMessageHandler
{
public:
    KeyExchanger(Transport& owner, Mode mode, const Hash::AType& hash);
    virtual void Start(void) = 0;
    
    void GenerateKeys(void);
    void NewKeys(void);
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
    const Hash::AType &_hash;
    Transport &_owner;
    Mode _mode;
};

/**
 * Interface for a host key algorithm, providing a means to verify a host key sent from a server.
 */
class IHostKeyAlgorithm
{
public:
    virtual ~IHostKeyAlgorithm() = default;
    
    /**
     * Confirm that a host key is acceptable (usually checking the key against a database in the local machine, or
     * asking the user about it).
     */
    virtual bool Confirm(Files::Format::IKeyFile& keyFile) = 0;
    
    /** Confirm the signature is valid. */
    virtual bool Verify(Files::Format::IKeyFile& keyFile, Types::Blob signature, Types::Blob exchangeHash) = 0;
    
    /**
     * For a server, compute the signature.
     */
    virtual Types::Blob Compute(Files::Format::IKeyFile& keyFile, Types::Blob message) = 0;
};

/**
 * Interface for implementing an encryption algorithm.
 */
class IEncryptionAlgorithm
{
public:
    virtual ~IEncryptionAlgorithm() = default;
    
    virtual int BlockSize(void) = 0;
    
    virtual Types::Blob Encrypt(Types::Blob data) = 0;
    virtual Types::Blob Decrypt(Types::Blob data) = 0;
};

/**
 * Interface for implementing an HMAC algorithm.
 */
class IHMACAlgorithm
{
public:
    virtual ~IHMACAlgorithm() = default;
    
    virtual Types::Blob Generate(Types::Blob packet) = 0;
    virtual int Length(void) = 0;
};

/**
 * Interface for implementing a compression algorithm.
 */
class ICompression
{
public:
    // TODO: Implement compression
};

/**
 * Interface for implementing a language.
 */
class ILanguage
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
    /**
     * Factory interface to produce an object. Used with Instantiable::Factory
     */
    template<class Base> class IInstantiator
    {
    public:
        virtual ~IInstantiator() = default;
        virtual std::shared_ptr<Base> Create(Transport& owner, Mode mode) const = 0;
    };
    
    std::map<std::string, std::shared_ptr<IInstantiator<KeyExchanger>>> supportedKeyExchanges;
    std::map<std::string, std::shared_ptr<IInstantiator<IHostKeyAlgorithm>>> serverHostKeyAlgorithms;
    std::map<std::string, std::shared_ptr<IInstantiator<IEncryptionAlgorithm>>> encryptionAlgorithms_clientToServer;
    std::map<std::string, std::shared_ptr<IInstantiator<IEncryptionAlgorithm>>> encryptionAlgorithms_serverToClient;
    std::map<std::string, std::shared_ptr<IInstantiator<IHMACAlgorithm>>> macAlgorithms_clientToServer;
    std::map<std::string, std::shared_ptr<IInstantiator<IHMACAlgorithm>>> macAlgorithms_serverToClient;
    std::map<std::string, std::shared_ptr<IInstantiator<ICompression>>> compressionAlgorithms_clientToServer;
    std::map<std::string, std::shared_ptr<IInstantiator<ICompression>>> compressionAlgorithms_serverToClient;
    std::map<std::string, std::shared_ptr<IInstantiator<ILanguage>>> languages_clientToServer;
    std::map<std::string, std::shared_ptr<IInstantiator<ILanguage>>> languages_serverToClient;
    
    /**
     * Template class to automate adding supported algorithms to a Configuration object.
     */
    template<class Class, class Base> class Instantiatable
    {
    private:
        class Factory : public IInstantiator<Base>
        {
        public:
            std::shared_ptr<Base> Create(Transport& owner, Mode mode) const override
            {
                return std::make_shared<Class>(owner, mode);
            }
        };
    public:
        static void Add(std::map<std::string, std::shared_ptr<IInstantiator<Base>>> &list)
        {
            list.insert(std::pair<std::string, std::shared_ptr<IInstantiator<Base>>>(std::string(Class::Name), std::make_shared<Factory>()));
        }
    };
};
    
/**
 * Utility "No compression" compression implementation
 */
class NoneCompression : public ICompression
{
public:
    static constexpr char Name[] = "none";
    class Factory : public Configuration::Instantiatable<NoneCompression, ICompression>
    {
    };
    
    NoneCompression(Transport& owner, Mode mode)
    {
    }
};

/**
 * Container for a packet for passing over an SSH transport.
 */
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

/**
 * SSH Transport class. Implements all machinery to send and receive SSH packets, including encryption/decryption,
 * HMAC checking and registration for services.
 */
class Transport
{
public:
    enum class PanicReason {
        OutOfRange,
        InvalidMessage,
        NoMatchingAlgorithm,
        BadHostKey,
        BadSignature,
        NoHostKey,
        DisconnectingForError,
    };
    static std::string StringForPanicReason(PanicReason reason);
    
    /**
     * Delegate callback for Transport events.
     */
    class IDelegate
    {
    public:
        virtual ~IDelegate() = default;
        
        virtual void Send(const void *data, UInt32 length) = 0;
        virtual void Failed(PanicReason reason) = 0;
        // For servers
        virtual std::shared_ptr<Files::Format::IKeyFile> GetHostKey(void) { throw new std::runtime_error("Not implemented"); }
    };
    
    // Internal
    std::shared_ptr<Internal::KexHandler> kexHandler;
    Types::Blob inputBuffer;
    void InitialiseSSH(std::string remoteVersion, const std::vector<std::string>& message);
    void HandlePacket(Packet block);
    void ResetAlgorithms(bool local);
    virtual void KeysChanged(void);
    std::shared_ptr<Files::Format::IKeyFile> GetHostKey(void) { return _delegate->GetHostKey(); }
    
    void Send(Types::Blob payload);
    void Panic(PanicReason r);
    void SkipPacket(void);
    
    void RegisterForPackets(IMessageHandler* handler, const Byte* number, int numberLength);
    void UnregisterForPackets(const Byte* number, int numberLength);
    // TODO; disable/etc.

public:
    Transport(Maths::IRandomSource& source, Mode transportType);
    
    // Network interface
    void SetDelegate(IDelegate* delegate);
    void Received(const void *data, UInt32 length);

    // Startup
    Internal::TransportInfo local, remote;
    std::shared_ptr<IHostKeyAlgorithm> hostKeyAlgorithm;
    std::optional<Types::Blob> sessionID;
    std::shared_ptr<KeyExchanger> keyExchanger;
    
    // Running
    std::shared_ptr<IEncryptionAlgorithm> encryptionToServer;
    std::shared_ptr<IEncryptionAlgorithm> encryptionToClient;
    std::shared_ptr<IHMACAlgorithm> macToServer;
    std::shared_ptr<IHMACAlgorithm> macToClient;
    
    // Supported
    Mode mode;
    Configuration configuration;
    Maths::IRandomSource &random;
    
    // Control
    void Start(void);
    void Disconnect(SSHDisconnect reason);
    
    // Utilities
    inline std::shared_ptr<IEncryptionAlgorithm> GetIncomingEncryption(void)
    {
        return (mode == Client) ? encryptionToClient : encryptionToServer;
    }
    inline std::shared_ptr<IEncryptionAlgorithm> GetOutgoingEncryption(void)
    {
        return (mode == Client) ? encryptionToServer : encryptionToClient;
    }
    inline std::shared_ptr<IHMACAlgorithm> GetIncomingHMAC(void)
    {
        return (mode == Client) ? macToClient : macToServer;
    }
    inline std::shared_ptr<IHMACAlgorithm> GetOutgoingHMAC(void)
    {
        return (mode == Client) ? macToServer : macToClient;
    }
    inline char Local(void) const
    {
        return (mode == Client) ? 'C' : 'S';
    }
    inline char Remote(void) const
    {
        return (mode == Client) ? 'S' : 'C';
    }

private:
    IDelegate *_delegate = nullptr;
    std::shared_ptr<Internal::Handler> _handler;
    IMessageHandler *_packeters[256];
    int _toSkip;
    UInt32 _localSeqCounter = 0;
    UInt32 _remoteSeqCounter = 0;
    UInt32 _localKeyCounter = 0;
    UInt32 _remoteKeyCounter = 0;
};

} // namespace minissh::Transport
