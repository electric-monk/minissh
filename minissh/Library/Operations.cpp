//
//  Operations.cpp
//  minissh
//
//  Created by Colin David Munro on 7/02/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#include "Operations.h"

// As per http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
// NIST Special Publication 800-38A 2001 Edition

namespace minissh::Algorithm {

OperationCBC::OperationCBC(Encryption& encryption, Types::Blob initialisationVector)
:Operation(encryption, initialisationVector)
{
}

Types::Blob OperationCBC::Encrypt(Types::Blob data)
{
    Types::Blob combined = data.XorWith(_currentVector);
    Types::Blob result = _encryption.Encrypt(combined);
    SetVector(result);
    return result;
}

Types::Blob OperationCBC::Decrypt(Types::Blob data)
{
    Types::Blob decrypted = _encryption.Decrypt(data);
    Types::Blob result = decrypted.XorWith(_currentVector);
    SetVector(data);
    return result;
}

OperationCTR::OperationCTR(Encryption& encryption, Types::Blob initialisationVector)
:Operation(encryption, initialisationVector.Copy())
{
}

Types::Blob OperationCTR::Encrypt(Types::Blob data)
{
    Types::Blob encrypted = _encryption.Encrypt(_currentVector);
    Types::Blob result = encrypted.XorWith(data);
    Step();
    return result;
}

Types::Blob OperationCTR::Decrypt(Types::Blob data)
{
    return Encrypt(data);
}

void OperationCTR::Step(void)
{
    // HACK: modify the blob
    int j = _currentVector.Length();
    Byte *values = (Byte*)_currentVector.Value();
    while (--j >= 0 && ++values[j] == 0);
}

} // namespace minissh::Algorithm
