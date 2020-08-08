//
//  Hash.h
//  minissh
//
//  Created by Colin David Munro on 9/02/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#pragma once

#include <optional>
#include "Types.h"

namespace minissh::Hash {

/**
 * Exception for hash code
 */
struct Exception : public std::runtime_error
{
    Exception(const char* const& message)
    :runtime_error(message)
    {}
};
   
/**
 * Exception specifically for 'message too long' RSA error.
 */
struct MessageTooLong : public Exception
{
    MessageTooLong()
    :Exception("Hash input too long")
    {}
};
   
/**
 * Abstract base class for providing an SSH hashing algorithm.
 */
class AType
{
public:
    /**
     * Abstract base class for implementing a general hashing algorithm.
     */
    class AToken
    {
    public:
        virtual void Update(const Byte *data, UInt32 length) = 0;
        virtual std::optional<Types::Blob> End(void) = 0;

        void Update(Types::Blob blob)
        {
            Update(blob.Value(), blob.Length());
        }

    protected:
        ~AToken() = default;
    };
    
    virtual Types::Blob EMSA_PKCS1_V1_5_Prefix(void) const = 0;
    virtual std::shared_ptr<AToken> Start(void) const = 0;
    virtual UInt64 DigestLength(void) const = 0;

    std::optional<Types::Blob> Compute(Types::Blob data) const
    {
        std::shared_ptr<AToken> token = Start();
        token->Update(data);
        return token->End();
    }
};

/**
 * Class implementing the SHA1 algorithm.
 */
class SHA1 : public AType
{
public:
    Types::Blob EMSA_PKCS1_V1_5_Prefix(void) const override;
    std::shared_ptr<AToken> Start(void) const override;
    virtual UInt64 DigestLength(void) const override;
};

} // namespace minissh::Hash
