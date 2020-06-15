//
//  hmac.h
//  minissh
//
//  Created by Colin David Munro on 9/02/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#pragma once

#include <memory>
#include "Types.h"
#include "Hash.h"

namespace minissh::HMAC {

Types::Blob Calculate(const Hash::Type& hash, Types::Blob key, Types::Blob text);

} // namespace minissh::HMAC
