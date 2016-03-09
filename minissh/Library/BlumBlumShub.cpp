//
//  BlumBlumShub.cpp
//  minissh
//
//  Created by Colin David Munro on 24/01/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#include <stdio.h>
#include "BlumBlumShub.h"
#include "Maths.h"

BlumBlumShub::BlumBlumShub(int bits, RandomSource *source)
{
    _n = GenerateN(bits, source);
    _state = NULL;
}

void BlumBlumShub::SetSeed(Byte *bytes, UInt32 length)
{
    BigNumber(bytes, length).Divide(_n, _state);
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

BigNumber BlumBlumShub::GetPrime(int bits, RandomSource *source)
{
    while (true) {
        BigNumber result = BigNumber(bits, source, 100);
        if ((result % 4) == 3)
            return result;
    }
}

BigNumber BlumBlumShub::GenerateN(int bits, RandomSource *source)
{
    BigNumber p = GetPrime(bits / 2, source);
    BigNumber q = GetPrime(bits / 2, source);
    while (p == q)
        q = GetPrime(bits, source);
    return p * q;
}
