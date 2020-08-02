//
//  Base64.h
//  libminissh
//
//  Created by Colin David Munro on 15/06/2020.
//  Copyright © 2020 MICE Software. All rights reserved.
//

#pragma once

#include "Types.h"

namespace minissh::Files::Base64 {
    
/**
 * Encode a binary blob into Base64
 */
Types::Blob Encode(Types::Blob raw);
    
/**
 * Decode a Base64 string into a binary blob
 */
Types::Blob Decode(Types::Blob text);
    
} // namespace minissh::Files
