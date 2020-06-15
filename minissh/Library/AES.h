//
//  AES.h
//  minissh
//
//  Created by Colin David Munro on 7/02/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#pragma once

#include "Encryption.h"

namespace minissh::Algorithm {

class AES : public Encryption
{
public:
    AES(Types::Blob key);

    Types::Blob Encrypt(Types::Blob data);
    Types::Blob Decrypt(Types::Blob data);
    
private:
    int _rounds;
    Types::Blob _expandedKey;
};

} // namespace minissh::Algorithm
