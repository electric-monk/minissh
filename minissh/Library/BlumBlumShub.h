//
//  BlumBlumShub.h
//  minissh
//
//  Created by Colin David Munro on 24/01/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#ifndef __minissh__BlumBlumShub__
#define __minissh__BlumBlumShub__

#include "Types.h"
#include "Maths.h"

class BlumBlumShub : public sshObject, public RandomSource
{
public:
    BlumBlumShub(int bits, RandomSource *source);
    
    void SetSeed(Byte *bytes, UInt32 length);
    
    // RandomSource
    UInt32 Random(void);
    
protected:
    ~BlumBlumShub();
    
private:
    static LargeNumber* GetPrime(int bits, RandomSource *source);
    static LargeNumber* GenerateN(int bits, RandomSource *source);
    
    LargeNumber *_state;
    LargeNumber *_n;
};

#endif /* defined(__minissh__BlumBlumShub__) */
