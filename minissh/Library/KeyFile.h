//
//  KeyFile.h
//  libminissh
//
//  Created by Colin David Munro on 22/06/2020.
//  Copyright © 2020 MICE Software. All rights reserved.
//

#pragma once

#include "Types.h"

namespace minissh::Files::Format {
    
/**
 * File format-specific exception.
 */
struct Exception : public std::runtime_error
{
    Exception(const char* const& message)
    :runtime_error(message)
    {}
};

/**
 * Supported file types.
 */
enum class FileType {
    DER,
    SSH,
};

/**
 * Abstract base class for any type of key. Simply provides a base so this code can load any supported key type,
 * instead of a specific one.
 */
class IKeyFile
{
public:
    virtual ~IKeyFile() = default;
    
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

/**
 * Base class to register a type of key, so that this code can automagically find it.
 */
class KeyFileLoaderImpl
{
public:
    std::string _name;
    FileType _type;
    KeyFileLoaderImpl *_last, *_next;

    virtual std::shared_ptr<IKeyFile> Execute(Types::Blob blob) = 0;
    virtual ~KeyFileLoaderImpl();

protected:
    KeyFileLoaderImpl(const std::string& name, FileType type);
};
    
/**
 * Template class to allow key file loaders to register with LoadKeys().
 */
template<typename T>
class KeyFileLoader : private KeyFileLoaderImpl
{
private:
    T callback;
    std::shared_ptr<IKeyFile> Execute(Types::Blob blob) override
    {
        return callback(blob);
    }
public:
    KeyFileLoader(const std::string& name, FileType type, T function)
    :KeyFileLoaderImpl(name, type), callback(function)
    {
    }
};

/**
 * Function to load a key file.
 */
std::shared_ptr<IKeyFile> LoadKeys(Types::Blob input);
    
/**
 * Function to save a key file with the specified options.
 */
Types::Blob SaveKeys(std::shared_ptr<IKeyFile> keys, FileType type, bool isPrivate /* versus public */);
    
} // namespace minissh::Files::Format
