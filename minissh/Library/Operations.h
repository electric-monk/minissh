//
//  Operations.h
//  minissh
//
//  Created by Colin David Munro on 7/02/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#pragma once

#include "Encryption.h"

namespace minissh::Algorithm {

class OperationCBC : public AOperation
{
public:
    OperationCBC(AEncryption& encryption, Types::Blob initialisationVector);
    
    Types::Blob Encrypt(Types::Blob data);
    Types::Blob Decrypt(Types::Blob data);
};

class OperationCTR : public AOperation
{
public:
    OperationCTR(AEncryption& encryption, Types::Blob initialisationVector);
    
    Types::Blob Encrypt(Types::Blob data);
    Types::Blob Decrypt(Types::Blob data);
    
private:
    void Step(void);
};

} // namespace minissh::Algorithm
