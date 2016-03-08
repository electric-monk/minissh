//
//  Operations.h
//  minissh
//
//  Created by Colin David Munro on 7/02/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#ifndef __minissh__Operations__
#define __minissh__Operations__

#include "Encryption.h"

class OperationCBC : public Operation
{
public:
    OperationCBC(Encryption *encryption, sshBlob *initialisationVector);
    
    sshBlob* Encrypt(sshBlob *data);
    sshBlob* Decrypt(sshBlob *data);
};

class OperationCTR : public Operation
{
public:
    OperationCTR(Encryption *encryption, sshBlob *initialisationVector);
    
    sshBlob* Encrypt(sshBlob *data);
    sshBlob* Decrypt(sshBlob *data);
    
private:
    void Step(void);
};

#endif /* defined(__minissh__Operations__) */
