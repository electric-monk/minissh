//
//  Transport.h
//  minissh
//
//  Created by Colin David Munro on 10/01/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#ifndef __minissh__Transport__
#define __minissh__Transport__

#include "Types.h"

class RandomSource;
class sshTransport;
class HashType;
class sshBlob;
class sshHMACAlgorithm;

namespace sshTransport_Internal {
    class Handler;
    class KexHandler;
    
    class TransportInfo
    {
    public:
        TransportInfo();
        ~TransportInfo();
        void Reset(void);
        
        sshString *version;
        sshNameList *message;
        sshBlob *kexPayload;
    };
}

typedef enum {
    Server,
    Client,
} TransportMode;

class sshConfiguration : public sshObject
{
public:
    sshConfiguration();
    
    sshDictionary *supportedKeyExchanges;
    sshDictionary *serverHostKeyAlgorithms;
    sshDictionary *encryptionAlgorithms_clientToServer;
    sshDictionary *encryptionAlgorithms_serverToClient;
    sshDictionary *macAlgorithms_clientToServer;
    sshDictionary *macAlgorithms_serverToClient;
    sshDictionary *compressionAlgorithms_clientToServer;
    sshDictionary *compressionAlgorithms_serverToClient;
    sshDictionary *languages_clientToServer;
    sshDictionary *languages_serverToClient;
    
    class Factory : public sshObject
    {
    public:
        template<class C> static void AddTo(sshDictionary *dictionary)
        {
            Factory *f = new C();
            sshString *temp = new sshString();
            temp->AppendFormat("%s", f->Name());
            dictionary->Set(temp, f);
            temp->Release();
            f->Release();
        }
        virtual const char* Name(void) const = 0;
        virtual sshObject* Instantiate(sshTransport *owner, TransportMode mode) const = 0;
    };
    template<class C> class FactoryTemplate : public Factory
    {
    public:
        sshObject* Instantiate(sshTransport *owner, TransportMode mode) const
        {
            sshObject *result = new C(owner, mode);
            result->Autorelease();
            return result;
        }
    };
    
protected:
    ~sshConfiguration();
};

class sshPacket : public sshBlob
{
public:
    sshPacket(sshTransport *owner);
    
    void Append(const Byte *bytes, int length);
    
    bool Satisfied(void);   // True when the whole packet is in and decoded
    UInt32 Requires(void);
    
    UInt32 PacketLength(void) const;
    UInt32 PaddingLength(void) const;
    sshBlob* Payload(void) const;
    sshBlob* Padding(void) const;
    sshBlob* MAC(void) const;
    
    bool CheckMAC(UInt32 sequenceNumber) const;
    
private:
    sshTransport *_owner;
    int _decodedBlocks, _requiredBlocks;
};

class sshMessageHandler : public sshObject
{
public:
    virtual void HandlePayload(sshBlob *data) = 0;
};

class sshKeyExchanger : public sshMessageHandler
{
public:
    sshKeyExchanger(sshTransport *owner, TransportMode mode);
    virtual void Start(void) = 0;
    
    void GenerateKeys(void);
    sshBlob* ExtendKey(sshBlob *baseKey, UInt32 requiredLength);
    
    HashType *hash;
    
    BigNumber key;
    sshString *exchangeHash;
    
    sshBlob *initialisationVectorC2S;
    sshBlob *initialisationVectorS2C;
    sshBlob *encryptionKeyC2S;
    sshBlob *encryptionKeyS2C;
    sshBlob *integrityKeyC2S;
    sshBlob *integrityKeyS2C;
protected:
    sshTransport *_owner;
    TransportMode _mode;
};

class sshHostKeyAlgorithm : public sshObject
{
public:
    // Confirm that a host key is acceptable (usually checking the key against a database in the local machine, or asking the user about it)
    virtual bool Confirm(sshString *hostKey) = 0;
    
    // Confirm the signature is valid
    virtual bool Verify(sshString *hostKey, sshString *signature, sshString *exchangeHash) = 0;
};

class sshEncryptionAlgorithm : public sshObject
{
public:
    virtual int BlockSize(void) = 0;
    
    virtual sshBlob* Encrypt(sshBlob *data) = 0;
    virtual sshBlob* Decrypt(sshBlob *data) = 0;
};

class sshHMACAlgorithm : public sshObject
{
public:
    virtual sshBlob* Generate(sshBlob *packet) = 0;
    virtual int Length(void) = 0;
};

class sshService : public sshObject
{
public:
    virtual bool EnableForAuthentication(void *data /* todo */) = 0;
};

class sshTransport : public sshObject
{
public:
    typedef enum {
        prOutOfRange,
        prInvalidMessage,
        prNoMatchingAlgorithm,
        prBadHostKey,
        prBadSignature,
    } PanicReason;
    
    class Delegate : public sshObject
    {
    public:
        virtual void Send(const void *data, UInt32 length) = 0;
        virtual void Failed(PanicReason reason) = 0;
    };
    
    // Internal
    sshTransport_Internal::KexHandler *kexHandler;
    sshBlob *inputBuffer;
    void InitialiseSSH(sshString *remoteVersion, sshNameList *message);
    void HandlePacket(sshPacket *block);
    void ResetAlgorithms(bool local);
    virtual void KeysChanged(void);
    
    void Send(sshBlob *payload);
    void Panic(PanicReason r);
    void SkipPacket(void);
    
    void RegisterForPackets(sshMessageHandler *handler, const Byte *number, int numberLength);
    void UnregisterForPackets(const Byte *number, int numberLength);
    // TODO; disable/etc.

public:
    sshTransport();
    
    // Network interface
    void SetDelegate(Delegate *delegate);
    void Received(const void *data, UInt32 length);

    // Startup
    sshTransport_Internal::TransportInfo local, remote;
    sshHostKeyAlgorithm *hostKeyAlgorithm;
    sshString *sessionID;
    sshKeyExchanger *keyExchanger;
    
    // Running
    sshEncryptionAlgorithm *encryptionToServer;
    sshEncryptionAlgorithm *encryptionToClient;
    sshHMACAlgorithm *macToServer;
    sshHMACAlgorithm *macToClient;
    
    // Supported
    TransportMode mode;
    sshConfiguration *configuration;
    RandomSource *random;
    
    // Control
    void Start(void);
    
protected:
    ~sshTransport();
    
private:
    Delegate *_delegate;
    sshTransport_Internal::Handler *_handler;
    sshMessageHandler *_packeters[256];
    int _toSkip;
    UInt32 _localSeqCounter, _remoteSeqCounter;
    UInt32 _localKeyCounter, _remoteKeyCounter;
    
    void SetHandler(sshTransport_Internal::Handler *handler);
};

#endif /* defined(__minissh__Transport__) */
