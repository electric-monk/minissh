//
//  TestRandom.h
//  minissh
//
//  Created by Colin David Munro on 3/08/2020.
//  Copyright © 2020 MICE Software. All rights reserved.
//

#pragma once

#include "Maths.h"

class TestRandom : public minissh::Maths::IRandomSource
{
public:
    TestRandom();
    
    minissh::UInt32 Random(void) override;
};
