//
//  Encryption.h
//  minissh
//
//  Created by Colin David Munro on 7/02/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#pragma once

#include <memory>
#include "Types.h"

namespace minissh::Algorithm {

class Encryption
{
public:
    Encryption(Types::Blob key);
    
    virtual Types::Blob Encrypt(Types::Blob data) = 0;
    virtual Types::Blob Decrypt(Types::Blob data) = 0;
    
protected:
    
    Types::Blob _key;
};

class Operation
{
public:
    Operation(Encryption& encryption, Types::Blob initialisationVector);
    
    virtual Types::Blob Encrypt(Types::Blob data) = 0;
    virtual Types::Blob Decrypt(Types::Blob data) = 0;
    
protected:
    
    Encryption& _encryption;
    Types::Blob _currentVector;
    
    void SetVector(Types::Blob vector);
};

} // namespace minissh::Algorithm
