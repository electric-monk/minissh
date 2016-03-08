//
//  SSH_AES.h
//  minissh
//
//  Created by Colin David Munro on 9/02/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#ifndef __minissh__aescbc__
#define __minissh__aescbc__

#include "Transport.h"

class AES;
class OperationCBC;
class OperationCTR;

class AES_CBC : public sshEncryptionAlgorithm
{
public:
    AES_CBC(sshTransport *owner, TransportMode mode, int keySize);
    
    int BlockSize(void);
    
    sshBlob* Encrypt(sshBlob *data);
    sshBlob* Decrypt(sshBlob *data);
  
protected:
    ~AES_CBC();
    
private:
    AES *_cypher;
    OperationCBC *_operation;
};

class AES128_CBC : public AES_CBC
{
public:
    AES128_CBC(sshTransport *owner, TransportMode mode)
    :AES_CBC(owner, mode, 128)
    {
    }

    class Factory : public sshConfiguration::FactoryTemplate<AES128_CBC>
    {
    public:
        const char* Name(void) const
        {
            return "aes128-cbc";
        }
    };
};

class AES192_CBC : public AES_CBC
{
public:
    AES192_CBC(sshTransport *owner, TransportMode mode)
    :AES_CBC(owner, mode, 192)
    {
    }
    
    class Factory : public sshConfiguration::FactoryTemplate<AES192_CBC>
    {
    public:
        const char* Name(void) const
        {
            return "aes192-cbc";
        }
    };
};

class AES256_CBC : public AES_CBC
{
public:
    AES256_CBC(sshTransport *owner, TransportMode mode)
    :AES_CBC(owner, mode, 256)
    {
    }
    
    class Factory : public sshConfiguration::FactoryTemplate<AES256_CBC>
    {
    public:
        const char* Name(void) const
        {
            return "aes256-cbc";
        }
    };
};

class AES_CTR : public sshEncryptionAlgorithm
{
public:
    AES_CTR(sshTransport *owner, TransportMode mode, int keySize);
    
    int BlockSize(void);
    
    sshBlob* Encrypt(sshBlob *data);
    sshBlob* Decrypt(sshBlob *data);
    
protected:
    ~AES_CTR();
    
private:
    AES *_cypher;
    OperationCTR *_operation;
};

class AES128_CTR : public AES_CTR
{
public:
    AES128_CTR(sshTransport *owner, TransportMode mode)
    :AES_CTR(owner, mode, 128)
    {
    }
    
    class Factory : public sshConfiguration::FactoryTemplate<AES128_CTR>
    {
    public:
        const char* Name(void) const
        {
            return "aes128-ctr";
        }
    };
};

class AES192_CTR : public AES_CTR
{
public:
    AES192_CTR(sshTransport *owner, TransportMode mode)
    :AES_CTR(owner, mode, 192)
    {
    }
    
    class Factory : public sshConfiguration::FactoryTemplate<AES192_CTR>
    {
    public:
        const char* Name(void) const
        {
            return "aes192-ctr";
        }
    };
};

class AES256_CTR : public AES_CTR
{
public:
    AES256_CTR(sshTransport *owner, TransportMode mode)
    :AES_CTR(owner, mode, 256)
    {
    }
    
    class Factory : public sshConfiguration::FactoryTemplate<AES256_CTR>
    {
    public:
        const char* Name(void) const
        {
            return "aes256-ctr";
        }
    };
};

#endif /* defined(__minissh__aescbc__) */
