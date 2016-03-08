//
//  Encryption.h
//  minissh
//
//  Created by Colin David Munro on 7/02/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#ifndef minissh_Encryption_h
#define minissh_Encryption_h

#include "Types.h"

class Encryption : public sshObject
{
public:
    Encryption(sshBlob *key);
    
    virtual sshBlob* Encrypt(sshBlob *data) = 0;
    virtual sshBlob* Decrypt(sshBlob *data) = 0;
    
protected:
    ~Encryption();
    
    sshBlob *_key;
};

class Operation : public sshObject
{
public:
    Operation(Encryption *encryption, sshBlob *initialisationVector);
    
    virtual sshBlob* Encrypt(sshBlob *data) = 0;
    virtual sshBlob* Decrypt(sshBlob *data) = 0;
    
protected:
    ~Operation();
    
    Encryption *_encryption;
    sshBlob *_currentVector;
    
    void SetVector(sshBlob *vector);
};

#endif
