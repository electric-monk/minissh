//
//  RSA.h
//  minissh
//
//  Created by Colin David Munro on 2/02/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#ifndef __minissh__RSA__
#define __minissh__RSA__

#include "Types.h"

class HashType;
class RandomSource;

namespace RSA {
    class Key : public sshObject
    {
    public:
        Key(BigNumber n, BigNumber e);
    
        BigNumber n;
        BigNumber e;
    };
    
    class KeySet : public sshObject
    {
    public:
        KeySet(RandomSource *random, int bits);
        
        Key *publicKey, *privateKey;
        
    protected:
        ~KeySet();
    };

    namespace SSA_PKCS1_V1_5 {
        sshBlob *Sign(Key *privateKey, sshBlob *M, HashType *hash);
        bool Verify(Key *publicKey, sshBlob *M, sshBlob *S, HashType *hash);
    }
}

#endif /* defined(__minissh__RSA__) */
