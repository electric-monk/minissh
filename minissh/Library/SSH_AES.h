//
//  SSH_AES.h
//  minissh
//
//  Created by Colin David Munro on 9/02/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#pragma once

#include "Transport.h"
#include "Operations.h"
#include "AES.h"

namespace minissh::Algorithm {

class AES_CBC : public Transport::EncryptionAlgorithm
{
public:
    AES_CBC(Transport::Transport& owner, Transport::Mode mode, int keySize);
    
    int BlockSize(void);
    
    Types::Blob Encrypt(Types::Blob data);
    Types::Blob Decrypt(Types::Blob data);
    
private:
    AES _cypher;
    OperationCBC _operation;
};

class AES128_CBC : public AES_CBC
{
public:
    AES128_CBC(Transport::Transport& owner, Transport::Mode mode)
    :AES_CBC(owner, mode, 128)
    {
    }

    static constexpr char Name[] = "aes128-cbc";
    class Factory : public Transport::Configuration::Instantiatable<AES128_CBC, Transport::EncryptionAlgorithm>
    {
    };
};

class AES192_CBC : public AES_CBC
{
public:
    AES192_CBC(Transport::Transport& owner, Transport::Mode mode)
    :AES_CBC(owner, mode, 192)
    {
    }
    
    static constexpr char Name[] = "aes192-cbc";
    class Factory : public Transport::Configuration::Instantiatable<AES192_CBC, Transport::EncryptionAlgorithm>
    {
    };
};

class AES256_CBC : public AES_CBC
{
public:
    AES256_CBC(Transport::Transport& owner, Transport::Mode mode)
    :AES_CBC(owner, mode, 256)
    {
    }
    
    static constexpr char Name[] = "aes256-cbc";
    class Factory : public Transport::Configuration::Instantiatable<AES256_CBC, Transport::EncryptionAlgorithm>
    {
    };
};

class AES_CTR : public Transport::EncryptionAlgorithm
{
public:
    AES_CTR(Transport::Transport& owner, Transport::Mode mode, int keySize);
    
    int BlockSize(void);
    
    Types::Blob Encrypt(Types::Blob data);
    Types::Blob Decrypt(Types::Blob data);
    
private:
    AES _cypher;
    OperationCTR _operation;
};

class AES128_CTR : public AES_CTR
{
public:
    AES128_CTR(Transport::Transport& owner, Transport::Mode mode)
    :AES_CTR(owner, mode, 128)
    {
    }
    
    static constexpr char Name[] = "aes128-ctr";
    class Factory : public Transport::Configuration::Instantiatable<AES128_CTR, Transport::EncryptionAlgorithm>
    {
    };
};

class AES192_CTR : public AES_CTR
{
public:
    AES192_CTR(Transport::Transport& owner, Transport::Mode mode)
    :AES_CTR(owner, mode, 192)
    {
    }
    
    static constexpr char Name[] = "aes192-ctr";
    class Factory : public Transport::Configuration::Instantiatable<AES192_CTR, Transport::EncryptionAlgorithm>
    {
    };
};

class AES256_CTR : public AES_CTR
{
public:
    AES256_CTR(Transport::Transport& owner, Transport::Mode mode)
    :AES_CTR(owner, mode, 256)
    {
    }
    
    static constexpr char Name[] = "aes256-ctr";
    class Factory : public Transport::Configuration::Instantiatable<AES256_CTR, Transport::EncryptionAlgorithm>
    {
    };
};

} // namespace minissh::Algorithm
