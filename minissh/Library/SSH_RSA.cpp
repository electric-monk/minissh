//
//  SSH_RSA.cpp
//  minissh
//
//  Created by Colin David Munro on 3/02/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#include "SSH_RSA.h"
#include "Maths.h"
#include "Hash.h"

SSH_RSA::SSH_RSA(sshTransport *owner, TransportMode mode)
{
    
}

bool SSH_RSA::Confirm(sshString *hostKey)
{
    // TODO: _owner->delegate->Confirm
    return true;
}

bool SSH_RSA::Verify(sshString *hostKey, sshString *signature, sshString *message)
{
    sshReader hostKeyReader(hostKey);
    sshString *tag = hostKeyReader.ReadString();
    if (!tag->IsEqual("ssh-rsa"))
        return false;
    BigNumber e = hostKeyReader.ReadMPInt();
    BigNumber n = hostKeyReader.ReadMPInt();
    RSA::Key *key = new RSA::Key(n, e);
    sshReader signatureReader(signature);
    sshString *tag2 = signatureReader.ReadString();
    if (!tag2->IsEqual("ssh-rsa"))
        return false;
    sshString *signatureString = signatureReader.ReadString();
    sshBlob *messageBlob = new sshBlob(message);
    sshBlob *signatureBlob = new sshBlob(signatureString);
    SHA1 hash;
    bool result = RSA::SSA_PKCS1_V1_5::Verify(key, messageBlob, signatureBlob, &hash);
    signatureBlob->Release();
    messageBlob->Release();
    key->Release();
    return result;
}
