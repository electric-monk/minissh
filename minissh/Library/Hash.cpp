//
//  Hash.cpp
//  minissh
//
//  Created by Colin David Munro on 9/02/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#include <memory.h>
#include "Hash.h"
#include "sha1.h"

HashType::Token::~Token()
{
}

class SHA1_Token : public HashType::Token
{
public:
    SHA1_Token()
    {
        SHA1_Init(&_context);
    }
    
    void Update(const Byte *data, UInt32 length)
    {
        SHA1_Update(&_context, data, length);
    }
    
    sshBlob* End(void)
    {
        Byte result[SHA1_DIGEST_SIZE];
        
        SHA1_Final(&_context, result);
        
        sshBlob *object = new sshBlob();
        object->Append(result, sizeof(result));
        object->Autorelease();
        
        delete this;
        return object;
    }
    
private:
    SHA1_CTX _context;
};

sshBlob* SHA1::EMSA_PKCS1_V1_5_Prefix(void)
{
    const Byte prefix[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
    sshBlob *object = new sshBlob();
    object->Append(prefix, sizeof(prefix));
    object->Autorelease();
    return object;
}

HashType::Token* SHA1::Start(void)
{
    return new SHA1_Token();
}
