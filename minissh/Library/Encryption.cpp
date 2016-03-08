#include "Encryption.h"

Encryption::Encryption(sshBlob *key)
{
    _key = key;
    _key->AddRef();
}

Encryption::~Encryption()
{
    _key->Release();
}

Operation::Operation(Encryption *encryption, sshBlob *initialisationVector)
{
    _encryption = encryption;
    _encryption->AddRef();
    _currentVector = initialisationVector;
    _currentVector->AddRef();
}

Operation::~Operation()
{
    _currentVector->Release();
    _encryption->Release();
}

void Operation::SetVector(sshBlob *vector)
{
    _currentVector->Release();
    _currentVector = vector;
    _currentVector->AddRef();
}
