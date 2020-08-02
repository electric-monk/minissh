//
//  KeyFile.hpp
//  libminissh
//
//  Created by Colin David Munro on 22/06/2020.
//  Copyright © 2020 MICE Software. All rights reserved.
//

#pragma once

#include "Types.h"

namespace minissh::Files::Format {
    
struct Exception : public std::runtime_error
{
    Exception(const char* const& message)
    :runtime_error(message)
    {}
};

enum class FileType {
    DER,
    SSH,
};

// Abstract base class for any type of key. Simply provides a base so this code can load any
// supported key type, instead of a specific one.
class KeyFile
{
public:
    virtual ~KeyFile() = default;
    
    virtual Types::Blob SavePublic(FileType type) = 0;
    virtual Types::Blob SavePrivate(FileType type)
    {
        throw new Exception("Attempting to save private key of a public key");
    }
    virtual std::string GetKeyName(FileType type, bool isPrivate)
    {
        throw new Exception("Unsupported file type");
    }
};

// Class to register a type of key, so that this code can automagically find it
class KeyFileLoaderImpl
{
public:
    std::string _name;
    FileType _type;
    KeyFileLoaderImpl *_last, *_next;

    virtual std::shared_ptr<KeyFile> Execute(Types::Blob blob) = 0;
    virtual ~KeyFileLoaderImpl();

protected:
    KeyFileLoaderImpl(const std::string& name, FileType type);
};
template<typename T>
class KeyFileLoader : private KeyFileLoaderImpl
{
private:
    T callback;
    std::shared_ptr<KeyFile> Execute(Types::Blob blob) override
    {
        return callback(blob);
    }
public:
    KeyFileLoader(const std::string& name, FileType type, T function)
    :KeyFileLoaderImpl(name, type), callback(function)
    {
    }
};

// Main API
std::shared_ptr<KeyFile> LoadKeys(Types::Blob input);
Types::Blob SaveKeys(std::shared_ptr<KeyFile> keys, FileType type, bool isPrivate);
    
} // namespace minissh::Files::Format
