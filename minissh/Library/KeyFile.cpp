//
//  KeyFile.cpp
//  libminissh
//
//  Created by Colin David Munro on 22/06/2020.
//  Copyright © 2020 MICE Software. All rights reserved.
//

#include "KeyFile.h"
#include "Base64.h"

namespace minissh::Files::Format {
    
namespace {
    
KeyFileLoaderImpl *LoaderStart = nullptr;
KeyFileLoaderImpl *LoaderEnd = nullptr;
    
template<typename T>
KeyFileLoaderImpl* EnumerateKeyFileLoaders(T callback, FileType type)
{
    for (KeyFileLoaderImpl *start = LoaderStart; start; start = start->_next) {
        if (start->_type != type)
            continue;
        if (callback(*start))
            return start;
    }
    return nullptr;
}

int Find(const Byte* data, int length, int offset, Byte value)
{
    for (int i = offset; i < length; i++) {
        if (data[i] == value)
            return i;
    }
    return -1;
}

constexpr char* DER_START = "-----BEGIN ";

}

KeyFileLoaderImpl::KeyFileLoaderImpl(const std::string& name, FileType type)
:_name(name), _type(type)
{
    _next = nullptr;
    _last = LoaderEnd;
    if (_last == nullptr)
        LoaderStart = this;
    else
        _last->_next = this;
    LoaderEnd = this;
}

KeyFileLoaderImpl::~KeyFileLoaderImpl()
{
    if (_last)
        _last->_next = _next;
    if (_next)
        _next->_last = _last;
    if (LoaderStart == this)
        LoaderStart = _next;
    if (LoaderEnd == this)
        LoaderEnd = _last;
}

std::shared_ptr<IKeyFile> LoadKeys(Types::Blob input)
{
    // Inspect first five bytes
    int length = input.Length();
    if (length < 5)
        throw Exception("File too short");
    const Byte *bytes = input.Value();
    int der_len = std::strlen(DER_START);
    if (std::memcmp(bytes, DER_START, der_len) == 0) {
        // Maybe a DER file
        const Byte *subbytes = bytes + der_len;
        int sublength = length - der_len;
        KeyFileLoaderImpl *impl = EnumerateKeyFileLoaders([subbytes, sublength](KeyFileLoaderImpl& loader){
            int type_len = (int)loader._name.length();
            if ((type_len + 5) > sublength)
                return false;
            if (std::memcmp(subbytes, loader._name.c_str(), type_len) != 0)
                return false;
            return std::memcmp(subbytes + type_len, "-----", 5) == 0;
        }, FileType::DER);
        if (impl) {
            // Consume data we just looked at
            input.FindLine();
            // Process Base64 (TODO: Make this more efficient)
            Types::Blob base64;
            while (input.Length()) {
                std::optional<std::string> line = input.FindLine();
                if (!line)
                    break;
                if (line->length() > 5) {
                    // Lazily look for end marker
                    if (std::memcmp(line->c_str(), "-----", 5) == 0)
                        break;
                }
                base64.Append((Byte*)line->c_str(), (int)line->length());
            }
            // Decode and complete
            return impl->Execute(Base64::Decode(base64));
        }
    } else {
        // See if it's an ssh file
        int found = Find(bytes, length, 0, ' ');
        if (found != -1) {
            std::string source((char*)bytes, found);
            KeyFileLoaderImpl *impl = EnumerateKeyFileLoaders([source](KeyFileLoaderImpl& loader){
                return loader._name.compare(source) == 0;
            }, FileType::SSH);
            if (impl) {
                input.Strip(0, found + 1);
                bytes = input.Value();
                length = input.Length();
                int end = Find(bytes, length, 0, ' ');
                if (end != -1)
                    input.Strip(end, length - end);
                // Decode and complete
                return impl->Execute(Base64::Decode(input));
            }
        }
    }
    return nullptr;
}
    
Types::Blob SaveKeys(std::shared_ptr<IKeyFile> keys, FileType type, bool isPrivate)
{
    std::string desc = keys->GetKeyName(type, isPrivate);
    Types::Blob base64 = Base64::Encode(isPrivate ? keys->SavePrivate(type) : keys->SavePublic(type));
    std::string before, after;
    int base64chop;
    switch (type) {
        // TODO: better string formatting, which apparenly is not in C++ until C++20
        case FileType::DER:
            before = DER_START;
            before.append(desc);
            before.append("-----\n");
            after = "-----END ";
            after.append(desc);
            after.append("-----\n");
            base64chop = 64;
            break;
        case FileType::SSH:
            before = desc;
            before.append(" ");
            after = " no@address\n";
            base64chop = 0;
            break;
        default:
            throw Exception("Unsupported file type");
    }
    Types::Blob result;
    Types::Writer writer(result);
    writer.Write(before);
    if (base64chop) {
        int index = 0;
        int total = base64.Length();
        while (total) {
            int writing = std::min(base64chop, total);
            writer.Write(base64, index, writing);
            writer.Write(std::string("\n"));
            index += writing;
            total -= writing;
        }
    } else {
        writer.Write(base64);
    }
    writer.Write(after);
    return result;
}

std::shared_ptr<IKeyFile> LoadSSHKeys(Types::Blob sshInput)
{
    Types::Blob copy(sshInput);
    Types::Reader reader(copy);
    std::string name = reader.ReadString().AsString();
    KeyFileLoaderImpl *impl = EnumerateKeyFileLoaders([name](KeyFileLoaderImpl& loader){
        return loader._name.compare(name) == 0;
    }, FileType::SSH);
    if (impl)
        return impl->Execute(sshInput);
    throw std::runtime_error("Unknown format");
}

Types::Blob SaveSSHKeys(std::shared_ptr<IKeyFile> keys, bool isPrivate)
{
    return isPrivate ? keys->SavePrivate(FileType::SSH) : keys->SavePublic(FileType::SSH);
}

} // namespace minissh::Files::Format
