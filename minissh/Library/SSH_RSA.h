//
//  SSH_RSA.h
//  minissh
//
//  Created by Colin David Munro on 3/02/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#pragma once

#include "Transport.h"
#include "RSA.h"

namespace minissh::Algoriths {

/**
 * RSA implementation for SSH.
 */
class SSH_RSA : public Transport::IHostKeyAlgorithm
{
public:
    SSH_RSA(Transport::Transport& owner, Transport::Mode mode);
    bool Confirm(Types::Blob hostKey) override;
    bool Verify(Types::Blob hostKey, Types::Blob signature, Types::Blob exchangeHash) override;

    static constexpr char Name[] = "ssh-rsa";
    class Factory : public Transport::Configuration::Instantiatable<SSH_RSA, Transport::IHostKeyAlgorithm>
    {
    };
};
    
} // namespace minissh::Algoriths
