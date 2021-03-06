//
//  BlumBlumShub.cpp
//  minissh
//
//  Created by Colin David Munro on 24/01/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#include <cstdio>
#include "BlumBlumShub.h"
#include "Maths.h"
#include "Primes.h"
#include "Hash.h"

namespace minissh::Random {

namespace {
    
Maths::BigNumber GenerateN(int bits, Maths::IRandomSource &source)
{
    Maths::BigNumber p = Maths::Primes::GetPrime(source, bits / 2);
    Maths::BigNumber q = Maths::Primes::GetPrime(source, bits / 2);
    while (p == q)
        q = Maths::Primes::GetPrime(source, bits);
    return p * q;
}

} // namespace

BlumBlumShub::BlumBlumShub(int bits, IRandomSource &source)
{
    _n = GenerateN(bits, source);
    _state = NULL;
}

void BlumBlumShub::SetSeed(Byte *bytes, UInt32 length)
{
    Maths::BigNumber(bytes, length).Divide(_n, _state);
}

UInt32 BlumBlumShub::Random(void)
{
    UInt32 result = 0;
    for (int i = (sizeof(UInt32) * 8); i != 0; i--) {
        _state = _state.PowerMod(2, _n);
        result = (result << 1) | (_state[0] ? 1 : 0);
    }
    return result;
}
    
} // namespace minissh::Random
