//
//  SSH_AES.cpp
//  minissh
//
//  Created by Colin David Munro on 9/02/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#include "SSH_AES.h"
#include "AES.h"
#include "Operations.h"

AES_CBC::AES_CBC(sshTransport *owner, TransportMode mode, int keySize)
{
    _cypher = new AES(owner->keyExchanger->ExtendKey((mode == Client) ? owner->keyExchanger->encryptionKeyC2S : owner->keyExchanger->encryptionKeyS2C, keySize / 8));
    _operation = new OperationCBC(_cypher, (mode == Client) ? owner->keyExchanger->initialisationVectorC2S : owner->keyExchanger->initialisationVectorS2C);
}

AES_CBC::~AES_CBC()
{
    _operation->Release();
    _cypher->Release();
}

int AES_CBC::BlockSize(void)
{
    return 16;
}

sshBlob* AES_CBC::Encrypt(sshBlob *data)
{
    return _operation->Encrypt(data);
}

sshBlob* AES_CBC::Decrypt(sshBlob *data)
{
    return _operation->Decrypt(data);
}

AES_CTR::AES_CTR(sshTransport *owner, TransportMode mode, int keySize)
{
    _cypher = new AES(owner->keyExchanger->ExtendKey((mode == Server) ? owner->keyExchanger->encryptionKeyC2S : owner->keyExchanger->encryptionKeyS2C, keySize / 8));
    _operation = new OperationCTR(_cypher, owner->keyExchanger->ExtendKey((mode == Server) ? owner->keyExchanger->initialisationVectorC2S : owner->keyExchanger->initialisationVectorS2C, keySize / 8));
}

AES_CTR::~AES_CTR()
{
    _operation->Release();
    _cypher->Release();
}

int AES_CTR::BlockSize(void)
{
    return 16;
}

sshBlob* AES_CTR::Encrypt(sshBlob *data)
{
    return _operation->Encrypt(data);
}

sshBlob* AES_CTR::Decrypt(sshBlob *data)
{
    return _operation->Decrypt(data);
}
