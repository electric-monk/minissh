//
//  Hash.cpp
//  minissh
//
//  Created by Colin David Munro on 9/02/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#include <memory.h>
#include "Hash.h"
#include "sha1.h"

namespace minissh::Hash {

namespace {
    
class SHA1_Token : public AType::AToken
{
public:
    SHA1_Token()
    {
        _context.Init();
    }
    
    void Update(const Byte *data, UInt32 length)
    {
        _context.Update(data, length);
    }
    
    std::optional<Types::Blob> End(void)
    {
        Byte result[SHA1_DIGEST_SIZE];
        _context.Final(result);
        Types::Blob object;
        object.Append(result, sizeof(result));
        return object;
    }
    
private:
    SHA1_CTX _context;
};
    
} // namespace

Types::Blob SHA1::EMSA_PKCS1_V1_5_Prefix(void) const
{
    static const Byte prefix[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
    return Types::Blob(prefix, sizeof(prefix));
}

std::shared_ptr<AType::AToken> SHA1::Start(void) const
{
    return std::make_shared<SHA1_Token>();
}

} // namespace minissh::Hash
