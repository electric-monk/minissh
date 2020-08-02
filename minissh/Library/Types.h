//
//  Types.h
//  minissh
//
//  Created by Colin David Munro on 10/01/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#pragma once

#ifdef _DEBUG
#define DEBUG_KEX
#define DEBUG_LOG_TRANSFER_INFO
#define DEBUG_LOG_STATE_INFO
#endif

#ifdef DEBUG_LOG_STATE_INFO
#define DEBUG_LOG_STATE(x)          printf x
#else
#define DEBUG_LOG_STATE(x)
#endif
#ifdef DEBUG_LOG_TRANSFER_INFO
#define DEBUG_LOG_TRANSFER(x)       printf x
#else
#define DEBUG_LOG_TRANSFER(x)
#endif

#include <memory>
#include <string>
#include <vector>
#include <optional>
#include "Maths.h"
#include "BaseTypes.h"

namespace minissh::Types {

class Blob;

class Blob
{
public:
    Blob();
    Blob(const Byte* data, int length);
    Blob(const Blob& other);
    ~Blob();

    const Byte* Value(void) const;
    int Length(void) const;
    
    bool Compare(const Blob& other) const;
    
    std::string AsString(void) const;
    
    Blob XorWith(const Blob& other) const;
    
    void DebugDump(void);
    
    Blob& operator=(Blob other)
    {
        std::swap(_max, other._max);
        std::swap(_len, other._len);
        std::swap(_value, other._value);
        return *this;
    }
    
    // Mutability
    void Reset(void);
    void Append(const Byte *bytes, int length);
    void Strip(int location, int length);
    Blob Copy(void) const;

    // Utility
    std::optional<std::string> FindLine(void);

private:
    Byte *_value;
    int _len, _max;
};

class Reader
{
public:
    Reader(const Blob& data, int offset = 0);
    
    Byte ReadByte(void);
    Blob ReadBytes(int length);
    bool ReadBoolean(void);
    UInt32 ReadUInt32(void);
    UInt64 ReadUInt64(void);
    Blob ReadString(void);
    Maths::BigNumber ReadMPInt(void);
    std::vector<std::string> ReadNameList(void);
    void SkipBytes(int length);
    
    int Remaining(void) { return _length; }
    
private:
    const Byte *_cursor;
    int _length;
    
    void Check(size_t length);
};

class Writer
{
public:
    Writer(Blob& output);
    
    void Write(Byte byte);
    void Write(Blob bytes, int offset = 0, int length = -1); // Unlike WriteString, this does not write length, merely appending the bytes
    void Write(const std::string& str); // Unlike WriteString, this does not write length, but appends the string
    void Write(bool boolean);
    void Write(UInt32 value);
    void Write(UInt64 value);
    void WriteString(Blob string);
    void WriteString(const std::string& string);
    void Write(const Maths::BigNumber& value);
    void Write(const std::vector<std::string>& nameList);
    
private:
    Blob &_blob;
};

} // namespace minissh::Types
