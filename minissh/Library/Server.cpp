//
//  Server.cpp
//  libminissh
//
//  Created by Colin David Munro on 1/08/2020.
//  Copyright © 2020 MICE Software. All rights reserved.
//

#include "Server.h"

namespace minissh::Core {
    
Server::Server(Maths::IRandomSource& source)
:Transport::Transport(source, ::minissh::Transport::Mode::Server)
{
    
}

} // namespace minissh::Core
