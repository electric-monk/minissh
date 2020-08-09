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
#include "KeyFile.h"

class RandomSource;

namespace minissh::RSA {
    
struct Exception : public std::runtime_error
{
    Exception(const char* const& message)
    :runtime_error(message)
    {}
};
    
class Key
{
public:
    Key(Maths::BigNumber n, Maths::BigNumber e);

    Maths::BigNumber n; // Modulus
    Maths::BigNumber e; // Exponent
};

class KeyPublic : public Files::Format::IKeyFile
{
public:
    KeyPublic(Types::Blob load, Files::Format::FileType type);
    
    Key PublicKey(void) const { return Key(_n, _e); }

    std::shared_ptr<Transport::IHostKeyAlgorithm> KeyAlgorithm(void) override;
    
    Types::Blob SavePublic(Files::Format::FileType type) override;
    std::string GetKeyName(Files::Format::FileType type, bool isPrivate) override;

protected:
    KeyPublic(){}

    Maths::BigNumber _n; // Modulus
    Maths::BigNumber _e; // Public Exponent
};
    
class KeySet : public KeyPublic
{
public:
    KeySet(Maths::IRandomSource& random, int bits);
    KeySet(Types::Blob load, Files::Format::FileType type);

    Key PrivateKey(void) const { return Key(_n, _d); }

    Types::Blob SavePrivate(Files::Format::FileType type) override;
    std::string GetKeyName(Files::Format::FileType type, bool isPrivate) override;

private:
    Maths::BigNumber _d; // Private Exponent
    // Unused, but stored on disk, so we keep it around
    Maths::BigNumber _p; // prime1
    Maths::BigNumber _q; // prime2
    
};

namespace SSA_PKCS1_V1_5 {
    std::optional<Types::Blob> Sign(const Key& privateKey, Types::Blob M, const Hash::AType& hash);
    bool Verify(const Key& publicKey, Types::Blob M, Types::Blob S, const Hash::AType& hash);
} // namespace SSA_PKCS1_V1_5

} // namespace minissh::RSA
