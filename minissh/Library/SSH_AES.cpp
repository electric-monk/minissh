//
//  SSH_AES.cpp
//  minissh
//
//  Created by Colin David Munro on 9/02/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#include "SSH_AES.h"
#include "AES.h"
#include "Operations.h"

namespace minissh::Algorithm {

AES_CBC::AES_CBC(Transport::Transport& owner, Transport::Mode mode, int keySize)
:_cypher(owner.keyExchanger->ExtendKey((mode == Transport::Client) ? owner.keyExchanger->encryptionKeyC2S : owner.keyExchanger->encryptionKeyS2C, keySize / 8))
,_operation(_cypher, (mode == Transport::Client) ? owner.keyExchanger->initialisationVectorC2S : owner.keyExchanger->initialisationVectorS2C)
{
}

int AES_CBC::BlockSize(void)
{
    return 16;
}

Types::Blob AES_CBC::Encrypt(Types::Blob data)
{
    return _operation.Encrypt(data);
}

Types::Blob AES_CBC::Decrypt(Types::Blob data)
{
    return _operation.Decrypt(data);
}

AES_CTR::AES_CTR(Transport::Transport& owner, Transport::Mode mode, int keySize)
:_cypher(owner.keyExchanger->ExtendKey((mode == Transport::Server) ? owner.keyExchanger->encryptionKeyC2S : owner.keyExchanger->encryptionKeyS2C, keySize / 8))
,_operation(_cypher, owner.keyExchanger->ExtendKey((mode == Transport::Server) ? owner.keyExchanger->initialisationVectorC2S : owner.keyExchanger->initialisationVectorS2C, keySize / 8))
{
}

int AES_CTR::BlockSize(void)
{
    return 16;
}

Types::Blob AES_CTR::Encrypt(Types::Blob data)
{
    return _operation.Encrypt(data);
}

Types::Blob AES_CTR::Decrypt(Types::Blob data)
{
    return _operation.Decrypt(data);
}
    
} // namespace minissh::Algorithm
