//
//  Hash.h
//  minissh
//
//  Created by Colin David Munro on 9/02/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#ifndef __minissh__Hash__
#define __minissh__Hash__

#include "Types.h"

class HashType
{
public:
    class Token
    {
    public:
        virtual void Update(const Byte *data, UInt32 length) = 0;
        virtual sshBlob* End(void) = 0;

        void Update(sshBlob *blob)
        {
            Update(blob->Value(), blob->Length());
        }

    protected:
        ~Token();
    };
    
    virtual sshBlob* EMSA_PKCS1_V1_5_Prefix(void) = 0;
    virtual Token* Start(void) = 0;

    sshBlob* Compute(sshBlob *data)
    {
        Token *token = Start();
        token->Update(data);
        return token->End();
    }
};

class SHA1 : public HashType
{
public:
    sshBlob* EMSA_PKCS1_V1_5_Prefix(void);
    Token* Start(void);
};

#endif /* defined(__minissh__Hash__) */
