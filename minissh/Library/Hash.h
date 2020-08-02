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

struct Exception : public std::runtime_error
{
    Exception(const char* const& message)
    :runtime_error(message)
    {}
};
    
struct MessageTooLong : public Exception
{
    MessageTooLong()
    :Exception("Hash input too long")
    {}
};
    
class Type
{
public:
    class Token
    {
    public:
        virtual void Update(const Byte *data, UInt32 length) = 0;
        virtual std::optional<Types::Blob> End(void) = 0;

        void Update(Types::Blob blob)
        {
            Update(blob.Value(), blob.Length());
        }

    protected:
        ~Token() = default;
    };
    
    virtual Types::Blob EMSA_PKCS1_V1_5_Prefix(void) const = 0;
    virtual std::shared_ptr<Token> Start(void) const = 0;

    std::optional<Types::Blob> Compute(Types::Blob data) const
    {
        std::shared_ptr<Token> token = Start();
        token->Update(data);
        return token->End();
    }
};

class SHA1 : public Type
{
public:
    Types::Blob EMSA_PKCS1_V1_5_Prefix(void) const override;
    std::shared_ptr<Token> Start(void) const override;
};

} // namespace minissh::Hash
