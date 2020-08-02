//
//  BlumBlumShub.h
//  minissh
//
//  Created by Colin David Munro on 24/01/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#pragma once

#include "Types.h"
#include "Maths.h"

namespace minissh::Random {

class BlumBlumShub : public Maths::IRandomSource
{
public:
    BlumBlumShub(int bits, Maths::IRandomSource &source);
    
    void SetSeed(Byte *bytes, UInt32 length);
    
    // RandomSource
    UInt32 Random(void);
    
private:
    Maths::BigNumber _state;
    Maths::BigNumber _n;
};

} // namespace minissh::Random
