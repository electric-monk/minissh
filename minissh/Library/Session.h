//
//  Session.h
//  minissh
//
//  Created by Colin David Munro on 20/02/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#pragma once

#include "Connection.h"

namespace minissh::Core {

class Session : public Connection::Channel
{
public:
    Session(Connection& owner);
    
    std::optional<Types::Blob> OpenInfo(std::string &nameOut, UInt32 &packetSize, UInt32 &windowSize) override;
    void Opened(Types::Blob data) override;
    void OpenFailed(UInt32 reason, const std::string& message, const std::string& languageTag) override;
    
    void ReceivedClose(void) override;
    void ReceivedData(Types::Blob data) override;
    void ReceivedExtendedData(UInt32 type, Types::Blob data) override;
    void ReceivedRequestResponse(bool success) override;
    
    void Send(const char *keystrokes, UInt32 length);
    
private:
    bool _shell;
};

} // namespace minissh::Core
