//
//  DiffieHellman.h
//  minissh
//
//  Created by Colin David Munro on 31/01/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#pragma once

#include "Transport.h"

class LargeNumber;

namespace minissh::Algorithms::DiffieHellman {

class Base : public Transport::KeyExchanger
{
public:
    Base(Transport::Transport& owner, Transport::Mode mode, Maths::BigNumber p, Maths::BigNumber g);
    
    void Start(void) override;
    
    void HandlePayload(Types::Blob data) override;
    
protected:
    ~Base();
    
private:
    Maths::BigNumber _p, _g;    // Prime and Generator
    
    Maths::BigNumber _xy;

    Maths::BigNumber _e, _f;
    
    Types::Blob _hostKey;
    
    bool CheckRange(const Maths::BigNumber &number);
    Types::Blob MakeHash(void);
};

class Group1 : public Base
{
public:
    static constexpr char Name[] = "diffie-hellman-group1-sha1";
    class Factory : public Transport::Configuration::Instantiatable<Group1, Transport::KeyExchanger>
    {
    };
    
    Group1(Transport::Transport& owner, Transport::Mode mode);
};

class Group14 : public Base
{
public:
    static constexpr char Name[] = "diffie-hellman-group14-sha1";
    class Factory : public Transport::Configuration::Instantiatable<Group14, Transport::KeyExchanger>
    {
    };

    Group14(Transport::Transport& owner, Transport::Mode mode);
};

} // namespace minissh::Algorithms::DiffieHellman
