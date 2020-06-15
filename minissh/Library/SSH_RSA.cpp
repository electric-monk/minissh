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

bool SSH_RSA::Confirm(Types::Blob hostKey)
{
    // TODO: _owner->delegate->Confirm
    return true;
}

bool SSH_RSA::Verify(Types::Blob hostKey, Types::Blob signature, Types::Blob exchangeHash)
{
    Types::Reader hostKeyReader(hostKey);
    std::string tag = hostKeyReader.ReadString().AsString();
    if (tag.compare("ssh-rsa") != 0)
        return false;
    Maths::BigNumber e = hostKeyReader.ReadMPInt();
    Maths::BigNumber n = hostKeyReader.ReadMPInt();
    RSA::Key key(n, e);
    
    Types::Reader signatureReader(signature);
    std::string tag2 = signatureReader.ReadString().AsString();
    if (tag2.compare("ssh-rsa") != 0)
        return false;
    Types::Blob signatureBlob = signatureReader.ReadString();
    
    return RSA::SSA_PKCS1_V1_5::Verify(key, exchangeHash, signatureBlob, Hash::SHA1());
}

} // namespace minissh::Algoriths
