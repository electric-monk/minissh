//
//  SSH_HMAC.h
//  minissh
//
//  Created by Colin David Munro on 9/02/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#pragma once

#include "Types.h"
#include "Transport.h"

namespace minissh::Algorithm {

/**
 * Class implementing "hmac-sha1" HMAC algorithm.
 */
class HMAC_SHA1 : public Transport::IHMACAlgorithm
{
public:
    HMAC_SHA1(Transport::Transport& owner, Transport::Mode mode);
    
    Types::Blob Generate(Types::Blob packet);
    
    int Length(void);
    
    static constexpr char Name[] = "hmac-sha1";
    class Factory : public Transport::Configuration::Instantiatable<HMAC_SHA1, Transport::IHMACAlgorithm>
    {
    };

private:
    Types::Blob _key;
};

} // namespace minissh::Algorithm
