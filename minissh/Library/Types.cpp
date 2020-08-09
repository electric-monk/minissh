//
//  Types.cpp
//  minissh
//
//  Created by Colin David Munro on 10/01/2016.
//  Copyright (c) 2016-2020 MICE Software. All rights reserved.
//

#include <stdio.h>
#include <stdarg.h>
#include <memory.h>
#include "Types.h"
#include "Maths.h"

#define GRAIN           128

namespace minissh::Types {

namespace {
    
int GETSIZE(int x)
{
    return x + GRAIN - (x % GRAIN);
}

UInt32 Swap32(UInt32 value)
{
    return ((value & 0xFF000000) >> 24) | ((value & 0x00FF0000) >> 8) | ((value & 0x0000FF00) << 8) | ((value & 0x000000FF) << 24);
}

UInt64 Swap64(UInt64 value)
{
    value = (value & 0x00000000FFFFFFFF) << 32 | (value & 0xFFFFFFFF00000000) >> 32;
    value = (value & 0x0000FFFF0000FFFF) << 16 | (value & 0xFFFF0000FFFF0000) >> 16;
    value = (value & 0x00FF00FF00FF00FF) << 8  | (value & 0xFF00FF00FF00FF00) >> 8;
    return value;
}

void RawDebugDump(const Byte *data, UInt32 length)
{
    for (UInt32 base = 0; base < length; base += 16) {
        const Byte *offset = data + base;
        UInt32 amount = length - base;
        printf("%.4x ", base);
        for (UInt32 digit = 0; digit < 16; digit++) {
            if (digit >= amount)
                printf("   ");
            else
                printf("%.2x ", offset[digit]);
        }
        if (amount > 16)
            amount = 16;
        for (UInt32 digit = 0; digit < amount; digit++)
            printf("%c", ((offset[digit] >= 32) && (offset[digit] < 127)) ? offset[digit] : '.');
        printf("\n");
    }
}

int MatchCharacters(const Byte *buffer, int bufferLength, const Byte *match, int matchLength)
{
    int index = 0;
    int found = -1;
    int matched = 0;
    while (index < bufferLength) {
        if (buffer[index] == match[matched]) {
            if (matched == 0)
                found = index;
            matched++;
            if (matched == matchLength)
                return found;
        } else {
            matched = 0;
        }
        index++;
    }
    return -1;
}

} // namespace

void Blob::DebugDump(void)
{
    RawDebugDump(_value, _len);
}

#pragma mark -
#pragma mark Blob

Blob::Blob()
{
    _max = GRAIN;
    _value = new Byte[_max];
    _len = 0;
}

Blob::Blob(const Byte* data, int length)
:_max(length + GRAIN), _len(length)
{
    _value = new Byte[_max];
    memcpy(_value, data, _len);
}

Blob::Blob(const Blob& other)
:_max(other._max), _len(other._len)
{
    _value = new Byte[_max];
    memcpy(_value, other._value, _len);
}

std::string Blob::AsString(void) const
{
    return std::string(reinterpret_cast<char*>(_value), _len);
}

Blob Blob::XorWith(const Blob& other) const
{
    if (_len != other._len)
        throw std::invalid_argument("Blobs are not same length");
    Blob result(_value, _len);
    for (int i = 0; i < _len; i++)
        result._value[i] ^= other._value[i];
    return result;
}

Blob::~Blob()
{
    delete[] _value;
}

void Blob::Reset(void)
{
    _len = 0;
}

void Blob::Append(const Byte *bytes, int length)
{
    if ((_len + length) > _max) {
        _max = GETSIZE(_len + length);
        Byte *newData = new Byte[_max];
        memcpy(newData, _value, _len);
        delete[] _value;
        _value = newData;
    }
    memcpy(_value + _len, bytes, length);
    _len += length;
}

void Blob::Strip(int location, int length)
{
    memmove(_value + location, _value + location + length, _len - (location + length));
    _len -= length;
}

const Byte* Blob::Value(void) const
{
    return _value;
}

int Blob::Length(void) const
{
    return _len;
}

bool Blob::Compare(const Blob& other) const
{
    if (_len != other._len)
        return false;
    if (_len == 0)
        return true;
    return memcmp(_value, other._value, _len) == 0;
}

Blob Blob::Copy(void) const
{
    Blob result;
    result.Append(_value, _len);
    return result;
}

std::optional<std::string> Blob::FindLine(void)
{
    constexpr Byte crlf[] = {13, 10};
    // Get raw buffer
    const Byte *bytes = Value();
    int length = Length();
    // Find CR-LF
    int tostrip = (int)sizeof(crlf);
    int location = MatchCharacters(bytes, length, crlf, tostrip);
    if (location == -1) {
        constexpr Byte lf[] = {10};
        // Turns out sometimes OpenSSH breaks the standard and only sends LF
        tostrip = (int)sizeof(lf);
        location = MatchCharacters(bytes, length, lf, tostrip);
    }
    if (location == -1)
        return {};
    // Make a string
    std::string result(reinterpret_cast<const char*>(bytes), location);
    // Remove used data
    Strip(0, location + tostrip);
    // Done
    return location > 0 ? std::optional<std::reference_wrapper<std::string>>{result} : std::nullopt;
}

#pragma mark -
#pragma mark Reader

Reader::Reader(const Blob& data, int offset)
{
    _cursor = data.Value();
    _length = data.Length();
    
    _cursor += offset;
    _length -= offset;
}

Byte Reader::ReadByte(void)
{
    Check(1);
    _length--;
    return *(_cursor++);
}

Blob Reader::ReadBytes(int length)
{
    Check(length);
    Blob result(_cursor, length);
    _cursor += length;
    _length -= length;
    return result;
}

bool Reader::ReadBoolean(void)
{
    return (bool)ReadByte();
}

UInt32 Reader::ReadUInt32(void)
{
    Check(sizeof(UInt32));
    UInt32 value = *(UInt32*)_cursor;
    _cursor += sizeof(UInt32);
    _length -= sizeof(UInt32);
    return Swap32(value);
}

UInt64 Reader::ReadUInt64(void)
{
    Check(sizeof(UInt64));
    UInt64 value = *(UInt64*)_cursor;
    _cursor += sizeof(UInt64);
    _length -= sizeof(UInt64);
    return Swap64(value);
}

Blob Reader::ReadString(void)
{
    return ReadBytes(ReadUInt32());
}

Maths::BigNumber Reader::ReadMPInt(void)
{
    Blob value = ReadString();
    if (value.Length() == 0)
        return 0;
    else
        return Maths::BigNumber(value.Value(), value.Length());
}

static void AddEntry(std::vector<std::string>& list, const char *s, int l)
{
    if (l <= 0)
        return;
    list.push_back(std::string(s, l));
}

std::vector<std::string> Reader::ReadNameList(void)
{
    Blob string = ReadString();
    std::vector<std::string> list;
    const char *s = (char*)string.Value();
    int j = string.Length();
    int base = 0;
    for (int i = 0; i < j; i++) {
        if (s[i] == ',') {
            AddEntry(list, s + base, i - base);
            base = i + 1;
        }
    }
    if (base < j)
        AddEntry(list, s + base, j - base);
    return list;
}

void Reader::SkipBytes(int length)
{
    Check(length);
    _cursor += length;
    _length -= length;
}

void Reader::Check(size_t length)
{
    if (length > _length)
        throw std::out_of_range("Ran out of data");
}

Writer::Writer(Blob& output)
:_blob(output)
{
}

void Writer::Write(Byte byte)
{
    _blob.Append(&byte, 1);
}

void Writer::Write(Blob bytes, int offset, int length)
{
    if (length == -1)
        length = bytes.Length() - offset;
    else if ((offset + length) > bytes.Length())
        throw std::out_of_range("Write out of range");
    _blob.Append(bytes.Value() + offset, length);
}

void Writer::Write(const std::string& str)
{
    _blob.Append((Byte*)str.c_str(), str.length());
}

void Writer::Write(bool boolean)
{
    Write(Byte(boolean ? 1 : 0));
}

void Writer::Write(UInt32 value)
{
    UInt32 raw = Swap32(value);
    _blob.Append((Byte*)&raw, sizeof(raw));
}

void Writer::Write(UInt64 value)
{
    UInt64 raw = Swap64(value);
    _blob.Append((Byte*)&raw, sizeof(raw));
}

void Writer::WriteString(Blob string)
{
    Write((UInt32)string.Length());
    Write(string);
}

void Writer::WriteString(const std::string& string)
{
    Write((UInt32)string.size());
    _blob.Append((Byte*)string.c_str(), (UInt32)string.size());
}

void Writer::Write(const Maths::BigNumber& value)
{
    WriteString(value.Data());
}

void Writer::Write(const std::vector<std::string>& nameList)
{
    Blob value;
    Byte c = 0;
    for (const std::string& name : nameList) {
        if (c)
            value.Append(&c, 1);
        else
            c = ',';
        value.Append(reinterpret_cast<const Byte*>(name.c_str()), static_cast<int>(name.length()));
    }
    WriteString(value);
}
    
} // namespace minissh::Types
