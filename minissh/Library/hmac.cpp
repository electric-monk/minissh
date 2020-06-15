//
//  hmac.cpp
//  minissh
//
//  Created by Colin David Munro on 9/02/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#include "hmac.h"
#include "Types.h"
#include "Hash.h"

namespace minissh::HMAC {

// RFC2104: hash(K ^ opad, hash(k ^ ipad, text))
Types::Blob Calculate(const Hash::Type& hash, Types::Blob key, Types::Blob text)
{
    // If key is longer than 64 bytes, hash it
    if (key.Length() > 64) {
        std::optional<Types::Blob> result = hash.Compute(key);
        if (!result)
            throw new std::runtime_error("Couldn't hash key");
        key = *result;
    }
    
    // Generate pads from keys
    Byte k_ipad[64], k_opad[64];
    memset(k_ipad, 0, sizeof(k_ipad));
    memset(k_opad, 0, sizeof(k_opad));
    memcpy(k_ipad, key.Value(), key.Length());
    memcpy(k_opad, key.Value(), key.Length());
    for (int i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }
    
    // Do inner hash
    std::shared_ptr<Hash::Type::Token> innerHash = hash.Start();
    innerHash->Update(k_ipad, sizeof(k_ipad));
    innerHash->Update(text);
    std::optional<Types::Blob> innerDigest = innerHash->End();
    if (!innerDigest)
        throw new std::runtime_error("Couldn't compute inner digest");
    
    // Do outer hash
    std::shared_ptr<Hash::Type::Token> outerHash = hash.Start();
    outerHash->Update(k_opad, sizeof(k_opad));
    outerHash->Update(*innerDigest);
    std::optional<Types::Blob> outerDigest = outerHash->End();
    if (!outerDigest)
        throw new std::runtime_error("Couldn't compute outer digest");
    return *outerDigest;
}

} // namespace minissh::HMAC
