//
//  SSH_HMAC.cpp
//  minissh
//
//  Created by Colin David Munro on 9/02/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#include "SSH_HMAC.h"
#include "hmac.h"
#include "Hash.h"

namespace minissh::Algorithm {

HMAC_SHA1::HMAC_SHA1(Transport::Transport& owner, Transport::Mode mode)
{
    _key = (mode == Transport::Server) ? owner.keyExchanger->integrityKeyC2S : owner.keyExchanger->integrityKeyS2C;
}

Types::Blob HMAC_SHA1::Generate(Types::Blob packet)
{
    return HMAC::Calculate(Hash::SHA1(), _key, packet);
}

int HMAC_SHA1::Length(void)
{
    return 20;
}

} // namespace minissh::Algorithm
