//
//  Operations.cpp
//  minissh
//
//  Created by Colin David Munro on 7/02/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#include "Operations.h"

// As per http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
// NIST Special Publication 800-38A 2001 Edition

OperationCBC::OperationCBC(Encryption *encryption, sshBlob *initialisationVector)
:Operation(encryption, initialisationVector)
{
}

sshBlob* OperationCBC::Encrypt(sshBlob *data)
{
    sshBlob *combined = data->XorWith(_currentVector);
    sshBlob *result = _encryption->Encrypt(combined);
    SetVector(result);
    return result;
}

sshBlob* OperationCBC::Decrypt(sshBlob *data)
{
    sshBlob *decrypted = _encryption->Decrypt(data);
    sshBlob *result = decrypted->XorWith(_currentVector);
    SetVector(data);
    return result;
}

static sshBlob* Copy(sshBlob *blob)
{
    sshBlob *result = new sshBlob();
    result->Append(blob->Value(), blob->Length());
    result->Autorelease();
    return result;
}

OperationCTR::OperationCTR(Encryption *encryption, sshBlob *initialisationVector)
:Operation(encryption, Copy(initialisationVector))
{
}

sshBlob* OperationCTR::Encrypt(sshBlob *data)
{
    sshBlob *encrypted = _encryption->Encrypt(_currentVector);
    sshBlob *result = encrypted->XorWith(data);
    Step();
    return result;
}

sshBlob* OperationCTR::Decrypt(sshBlob *data)
{
    return Encrypt(data);
}

void OperationCTR::Step(void)
{
    // HACK: modify the blob
    int j = _currentVector->Length();
    Byte *values = (Byte*)_currentVector->Value();
    while (--j >= 0 && ++values[j] == 0);
}
