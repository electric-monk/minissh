//
//  RSA.h
//  minissh
//
//  Created by Colin David Munro on 2/02/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#pragma once

#include <memory>
#include "Types.h"
#include "Hash.h"

class RandomSource;

namespace minissh::RSA {
    
class Key
{
public:
    Key(Maths::BigNumber n, Maths::BigNumber e);

    Maths::BigNumber n;
    Maths::BigNumber e;
};

class KeySet
{
public:
    KeySet(Maths::RandomSource& random, int bits);
    
    Key *publicKey, *privateKey;
};

namespace SSA_PKCS1_V1_5 {
    std::optional<Types::Blob> Sign(const Key& privateKey, Types::Blob M, const Hash::Type& hash);
    bool Verify(const Key& publicKey, Types::Blob M, Types::Blob S, const Hash::Type& hash);
} // namespace SSA_PKCS1_V1_5

} // namespace minissh::RSA
