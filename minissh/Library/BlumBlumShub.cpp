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
    _n->AddRef();
    _state = NULL;
}

BlumBlumShub::~BlumBlumShub()
{
    if (_state)
        _state->Release();
    _n->Release();
}

void BlumBlumShub::SetSeed(Byte *bytes, UInt32 length)
{
    LargeNumber *seed = new LargeNumber(bytes, length);
    if (_state)
        _state->Release();
    seed->Divide(_n, &_state);
}

UInt32 BlumBlumShub::Random(void)
{
    UInt32 result = 0;
    LargeNumber *two = new LargeNumber(2);
    for (int i = (sizeof(UInt32) * 8); i != 0; i--) {
        LargeNumber *newState = _state->PowerMod(two, _n);
        _state->Release();
        newState->AddRef();
        _state = newState;
        result = (result << 1) | (_state->IsBitSet(0) ? 1 : 0);
    }
    two->Release();
    return result;
}

LargeNumber* BlumBlumShub::GetPrime(int bits, RandomSource *source)
{
    LargeNumber *result = NULL;
    {
        sshObject::Releaser releaser;
        LargeNumber *four = new LargeNumber(4);
        LargeNumber *three = new LargeNumber(3);
        while (true) {
            releaser.Flush();
            result = new LargeNumber(bits, source, 100);
            LargeNumber *rem;
            result->Divide(four, &rem);
            bool match = rem->Compare(three) == 0;
            rem->Release();
            if (match)
                break;
            result->Release();
        }
        four->Release();
        three->Release();
    }
    if (result)
        result->Autorelease();
    return result;
}

LargeNumber* BlumBlumShub::GenerateN(int bits, RandomSource *source)
{
    LargeNumber *p = GetPrime(bits / 2, source);
    LargeNumber *q = GetPrime(bits / 2, source);
    while (p->Compare(q) == 0)
        q = GetPrime(bits, source);
    return p->Multiply(q);
}
