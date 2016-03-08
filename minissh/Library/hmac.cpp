//
//  hmac.cpp
//  minissh
//
//  Created by Colin David Munro on 9/02/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#include <memory.h>
#include "hmac.h"
#include "RSA.h"    // For "HashType", move it later
#include "Types.h"
#include "Hash.h"

// RFC2104: hash(K ^ opad, hash(k ^ ipad, text))
sshBlob* HMAC(HashType *hash, sshBlob *key, sshBlob *text)
{
    // If key is longer than 64 bytes, hash it
    if (key->Length() > 64)
        key = hash->Compute(key);
    
    // Generate pads from keys
    Byte k_ipad[64], k_opad[64];
    memset(k_ipad, 0, sizeof(k_ipad));
    memset(k_opad, 0, sizeof(k_opad));
    memcpy(k_ipad, key->Value(), key->Length());
    memcpy(k_opad, key->Value(), key->Length());
    for (int i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }
    
    // Do inner hash
    HashType::Token *innerHash = hash->Start();
    innerHash->Update(k_ipad, sizeof(k_ipad));
    innerHash->Update(text);
    sshBlob *innerDigest = innerHash->End();
    
    // Do outer hash
    HashType::Token *outerHash = hash->Start();
    outerHash->Update(k_opad, sizeof(k_opad));
    outerHash->Update(innerDigest);
    return outerHash->End();
}
