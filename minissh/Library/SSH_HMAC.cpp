//
//  SSH_HMAC.cpp
//  minissh
//
//  Created by Colin David Munro on 9/02/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#include "SSH_HMAC.h"
#include "hmac.h"
#include "Hash.h"

HMAC_SHA1::HMAC_SHA1(sshTransport *owner, TransportMode mode)
{
    _key = (mode == Server) ? owner->keyExchanger->integrityKeyC2S : owner->keyExchanger->integrityKeyS2C;
    _key->AddRef();
}

HMAC_SHA1::~HMAC_SHA1()
{
    _key->Release();
}

sshBlob* HMAC_SHA1::Generate(sshBlob *packet)
{
    SHA1 hash;
    return HMAC(&hash, _key, packet);
}

int HMAC_SHA1::Length(void)
{
    return 20;
}
