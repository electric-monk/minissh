#include "Encryption.h"

namespace minissh::Algorithm {

Encryption::Encryption(Types::Blob key)
:_key(key)
{
}

Operation::Operation(Encryption& encryption, Types::Blob initialisationVector)
:_encryption(encryption), _currentVector(initialisationVector)
{
}

void Operation::SetVector(Types::Blob vector)
{
    _currentVector = vector;
}

} // namespace minissh::Algorithm
