//
//  SSH_RSA.cpp
//  minissh
//
//  Created by Colin David Munro on 3/02/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#include "SSH_RSA.h"
#include "Maths.h"
#include "Hash.h"

namespace minissh::Algoriths {

SSH_RSA::SSH_RSA(Transport::Transport& owner, Transport::Mode mode)
{
}

bool SSH_RSA::Confirm(Files::Format::IKeyFile& keyFile)
{
    // TODO: _owner->delegate->Confirm
    return true;
}

bool SSH_RSA::Verify(Files::Format::IKeyFile& keyFile, Types::Blob signature, Types::Blob message)
{
    RSA::KeyPublic *publicKey = dynamic_cast<RSA::KeyPublic*>(&keyFile);
    if (!publicKey)
        return false;
    
    Types::Reader signatureReader(signature);
    if (signatureReader.ReadString().AsString().compare(Name) != 0)
        return false;
    Types::Blob signatureBlob = signatureReader.ReadString();
    
    return RSA::SSA_PKCS1_V1_5::Verify(publicKey->PublicKey(), message, signatureBlob, Hash::SHA1());
}

Types::Blob SSH_RSA::Compute(Files::Format::IKeyFile& keyFile, Types::Blob message)
{
    RSA::KeySet *privateKey = dynamic_cast<RSA::KeySet*>(&keyFile);
    if (!privateKey)
        throw new std::runtime_error("Unsupported private key");
    std::optional<Types::Blob> signature = RSA::SSA_PKCS1_V1_5::Sign(privateKey->PrivateKey(), message, Hash::SHA1());
    if (!signature)
        throw new std::runtime_error("Unable to sign");
    Types::Blob result;
    Types::Writer writer(result);
    writer.WriteString(Name);
    writer.WriteString(*signature);
    return result;
}

} // namespace minissh::Algoriths
