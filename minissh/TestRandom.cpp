//
//  TestRandom.cpp
//  minissh
//
//  Created by Colin David Munro on 3/08/2020.
//  Copyright © 2020 MICE Software. All rights reserved.
//

#include "TestRandom.h"

TestRandom::TestRandom()
{
    srand(time(NULL));
}

minissh::UInt32 TestRandom::Random(void)
{
    // WARNING: This is not secure, but just for testing.
    return rand();
}
