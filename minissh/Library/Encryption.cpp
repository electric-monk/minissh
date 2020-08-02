#include "Encryption.h"

namespace minissh::Algorithm {

AEncryption::AEncryption(Types::Blob key)
:_key(key)
{
}

AOperation::AOperation(AEncryption& encryption, Types::Blob initialisationVector)
:_encryption(encryption), _currentVector(initialisationVector)
{
}

void AOperation::SetVector(Types::Blob vector)
{
    _currentVector = vector;
}

} // namespace minissh::Algorithm
