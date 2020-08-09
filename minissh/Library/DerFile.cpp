//
//  DerFile.cpp
//  libminissh
//
//  Created by Colin David Munro on 16/06/2020.
//  Copyright © 2020 MICE Software. All rights reserved.
//

#include "DerFile.h"
#include "Types.h"
#include "Maths.h"

namespace minissh::Files::DER {
    
namespace {
    
// From https://docs.microsoft.com/en-gb/windows/win32/seccertenroll/about-der-encoding-of-asn-1-types
    
constexpr minissh::Byte BOOLEAN = 0x01;
constexpr minissh::Byte INTEGER = 0x02;
constexpr minissh::Byte BIT_STRING = 0x03;
constexpr minissh::Byte OCTET_STRING = 0x04;
constexpr minissh::Byte NULL_VALUE = 0x05;
constexpr minissh::Byte OBJECT_IDENTIFIER = 0x06;
constexpr minissh::Byte UTF8_STRING = 0x0C;
constexpr minissh::Byte PRINTABLE_STRING = 0x13;
constexpr minissh::Byte IA5_STRING = 0x16;
constexpr minissh::Byte BMP_STRING = 0x1E;
constexpr minissh::Byte SEQUENCE = 0x30;
constexpr minissh::Byte SET = 0x31;

}

namespace Reader {

namespace {

class Core
{
private:
    void Recurse(UInt64 size)
    {
        if (size == 0)
            return;
        UInt64 expected = _reader.Remaining() - size;
        do {
            Parse();
        } while (_reader.Remaining() > expected);
        if (expected != _reader.Remaining())
            throw std::runtime_error("Confused too much data");
    }
    
    std::vector<UInt32> ObjectIdentifier(const Types::Blob& data)
    {
        std::vector<UInt32> result;
        Types::Reader idReader(data);
        if (idReader.Remaining() < 1) {
            // Malformed input
            return result;
        }
        // Get special first two digits
        {
            Byte first = 0;
            Byte second = idReader.ReadByte();
            while ((first < 2) && (second >= 40)) {
                first++;
                second -= 40;
            }
            result.push_back(first);
            result.push_back(second);
        }
        // Get remaining LEB128 digits
        UInt32 value = 0, current = 0x80;
        while (idReader.Remaining()) {
            current = idReader.ReadByte();
            value = (value << 7) | (current & 0x7F);
            if (!(current & 0x80)) {
                result.push_back(value);
                value = 0;
                current = 0x80;
            }
        }
        if (!(current & 0x80)) {
            // Malformed input? Note it anyway
            result.push_back(value);
        }
        return result;
    }
public:
    Core(ICallback& callbacks, Types::Blob data)
    :_callbacks(callbacks), _reader(data)
    {
    }
    
    void Parse(void)
    {
        minissh::Byte type = _reader.ReadByte();
        minissh::UInt64 size = _reader.ReadByte();
        if (size & 0x80) {
            minissh::Byte byteCount = size & 0x7F;
            size = 0;
            for (int i = 0; i < byteCount; i++)
                size = (size << 8) | _reader.ReadByte();
        }
        switch (type) {
            case INTEGER:
                _callbacks.ReadInteger(Maths::BigNumber(_reader.ReadBytes(size).Value(), size));
                break;
            case OBJECT_IDENTIFIER:
                _callbacks.ReadObjectIdentifier(ObjectIdentifier(_reader.ReadBytes(size)));
                break;
            case NULL_VALUE:
                _callbacks.ReadNull();
                // Length should be 0
                break;
            case SEQUENCE:
                _callbacks.StartSequence();
                Recurse(size);
                _callbacks.EndSequence();
                break;
            case SET:
                _callbacks.StartSet();
                Recurse(size);
                _callbacks.EndSet();
                break;
            default:
                _callbacks.Unknown(type, _reader.ReadBytes(size));
                break;
        }
    }

private:
    ICallback &_callbacks;
    Types::Reader _reader;
};

} // namespace
    
void Load(minissh::Types::Blob input, ICallback& callbacks)
{
    Core(callbacks, input).Parse();
}

} // namespace Reader
    
namespace Writer {
    
namespace {
    
void WriteLength(Types::Writer& writer, UInt64 length, Byte byteCount)
{
    if (!length) {
        writer.Write(Byte(0x80 | byteCount));
    } else {
        WriteLength(writer, length >> 8, byteCount + 1);
        writer.Write(Byte(length & 0xFF));
    }
}
    
void WriteLength(Types::Writer& writer, UInt64 length)
{
    if (length < 0x80)
        writer.Write(Byte(length));
    else
        WriteLength(writer, length, 0);
}
    
void SaveHeader(Types::Writer& writer, Byte type, UInt64 length)
{
    writer.Write(type);
    WriteLength(writer, length);
}

void LEB128_Encode(Types::Writer &writer, uint32_t value, Byte recursed = 0)
{
    if (recursed && !value)
        return;
    LEB128_Encode(writer, value >> 7, 1 << 7);
    writer.Write(Byte((value & ((1 << 7) - 1)) & recursed));
}

} // namespace
    
Container::Container(Byte type)
:_type(type)
{
}

Types::Blob Container::Save(void)
{
    // TODO: Efficiency
    Types::Blob temp;
    Types::Writer tempWrite(temp);
    for (std::shared_ptr<IBase> item : components)
        tempWrite.Write(item->Save());
    // Write header
    Types::Blob result;
    Types::Writer resultWrite(result);
    SaveHeader(resultWrite, _type, temp.Length());
    resultWrite.Write(temp);
    return result;
}
    
Sequence::Sequence()
:Container(SEQUENCE)
{
}
    
Set::Set()
:Container(SET)
{
}
    
Types::Blob Integer::Save(void)
{
    Types::Blob temp = value.Data();
    Types::Blob result;
    Types::Writer resultWrite(result);
    SaveHeader(resultWrite, INTEGER, temp.Length());
    resultWrite.Write(temp);
    return result;
}

Types::Blob ObjectIdentifier::Save(void)
{
    if (components.size() < 2)
        throw std::invalid_argument("OBJECT IDENTIFIER requires a minimum of two values");
    // TODO: Efficiency
    Types::Blob temp;
    Types::Writer tempWrite(temp);
    // First two digits are special cased
    uint32_t first = components[0];
    uint32_t second = components[1];
    if (first > 2)
        throw std::invalid_argument("OBJECT IDENTIFIER first value must be 0, 1 or 2");
    if (first == 2) {
        if (second > 175)
            throw std::invalid_argument("OBJECT IDENTIFIER second value must be of value 0 to 175");
    } else {
        if (second > 39)
            throw std::invalid_argument("OBJECT IDENTIFIER second value must be of value 0 to 39");
    }
    tempWrite.Write(Byte((first * 40) + second));
    // Save any subsequent integers
    for (auto it = components.begin() + 2; it != components.end(); it++)
        LEB128_Encode(tempWrite, *it);
    // Generate wrapping result
    Types::Blob result;
    Types::Writer resultWrite(result);
    SaveHeader(resultWrite, OBJECT_IDENTIFIER, temp.Length());
    resultWrite.Write(temp);
    return result;
}

Null::Null()
{
}

Types::Blob Null::Save(void)
{
    Types::Blob result;
    Types::Writer resultWrite(result);
    SaveHeader(resultWrite, NULL_VALUE, 0);
    return result;
}

} // namespace Writer

} // namespace minissh::Files::DER
