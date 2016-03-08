//
//  Types.cpp
//  minissh
//
//  Created by Colin David Munro on 10/01/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#include <stdio.h>
#include <stdarg.h>
#include <memory.h>
#include "Types.h"
#include "Maths.h"

#define GRAIN           128

static int GETSIZE(int x)
{
    return x + GRAIN - (x % GRAIN);
}

static UInt32 Swap32(UInt32 value)
{
    return ((value & 0xFF000000) >> 24) | ((value & 0x00FF0000) >> 8) | ((value & 0x0000FF00) << 8) | ((value & 0x000000FF) << 24);
}

static UInt64 Swap64(UInt64 value)
{
    value = (value & 0x00000000FFFFFFFF) << 32 | (value & 0xFFFFFFFF00000000) >> 32;
    value = (value & 0x0000FFFF0000FFFF) << 16 | (value & 0xFFFF0000FFFF0000) >> 16;
    value = (value & 0x00FF00FF00FF00FF) << 8  | (value & 0xFF00FF00FF00FF00) >> 8;
    return value;
}

static void DebugDump(const Byte *data, UInt32 length)
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

void sshBlob::DebugDump(void)
{
    ::DebugDump(_value, _len);
}

void sshString::DebugDump(void)
{
    ::DebugDump((Byte*)_data, _len);
}

#pragma mark -
#pragma mark sshObject::Releaser

namespace sshObject_Releaser {
    class Container
    {
    public:
        Container(sshObject_Releaser::Container **root, sshObject *object)
        {
            if (object == NULL)
                throw "Error";
            _object = object;
            _next = *root;
            *root = this;
        }
        ~Container()
        {
            _object->Release();
            if (_next)
                delete _next;
        }
    private:
        Container *_next;
        sshObject *_object;
    };
    
    sshObject::Releaser *activeReleaser = NULL; // TODO: TLS
}

sshObject::Releaser::Releaser()
{
    _other = sshObject_Releaser::activeReleaser;
    sshObject_Releaser::activeReleaser = this;
    _data = NULL;
}

sshObject::Releaser::~Releaser()
{
    Flush();
    sshObject_Releaser::activeReleaser = (sshObject::Releaser*)_other;
}

void sshObject::Releaser::Flush(void)
{
    delete (sshObject_Releaser::Container*)_data;
    _data = NULL;
}

#pragma mark -
#pragma mark sshObject

sshObject::sshObject()
{
    _refCount = 1;
}

void sshObject::AddRef(void)
{
    _refCount++;
}

void sshObject::Release(void)
{
    _refCount--;
    if (_refCount == 0)
        delete this;
}

void sshObject::Autorelease(void)
{
    new sshObject_Releaser::Container((sshObject_Releaser::Container**)&sshObject_Releaser::activeReleaser->_data, this);
}

#pragma mark -
#pragma mark sshString

sshString::sshString()
{
    _max = GRAIN;
    _data = new char[_max];
    _len = 0;
}

sshString::sshString(sshBlob *blob)
{
    _max = blob->Length();
    _data = new char[_max];
    _len = _max;
    memcpy(_data, blob->Value(), _len);
}

sshString::~sshString()
{
    delete[] _data;
}

const char* sshString::Value(void) const
{
    return _data;
}

int sshString::Length() const
{
    return _len;
}

bool sshString::IsEqual(const sshString *other) const
{
    if (other == this)
        return true;
    if (other == NULL)
        return false;
    if (_len != other->_len)
        return false;
    return memcmp(_data, other->_data, _len) == 0;
}

bool sshString::IsEqual(const char *other) const
{
    int i;

    for (i = 0; (i < _len) && (other[i] != '\0'); i++)
        if (other[i] != _data[i])
            return false;
    return (i == _len) && (other[i] == '\0');
}

void sshString::Reset(void)
{
    _len = 0;
}

void sshString::CheckSize(int length)
{
    if (_max < length) {
        _max = GETSIZE(length + _len);
        char *newData = new char[_max];
        memcpy(newData, _data, _len);
        delete[] _data;
        _data = newData;
    }
}

void sshString::AppendFormat(const char *format, ...)
{
    va_list args, args2;
    int required;
    
    va_start(args, format);
    va_copy(args2, args);
    required = vsnprintf(NULL, 0, format, args) + 1; // +1 for the NUL we don't even use
    va_end(args);
    CheckSize(required + _len);
    _len += vsnprintf(_data + _len, _max - _len, format, args2);
    va_end(args2);
}

void sshString::Append(const char *bytes, int length)
{
    CheckSize(length + _len);
    memcpy(_data + _len, bytes, length);
    _len += length;
}

void sshString::Append(sshString *string)
{
    CheckSize(string->_len + _len);
    memcpy(_data + _len, string->_data, string->_len);
    _len += string->_len;
}

sshBlob* sshString::AsBlob(void)
{
    sshBlob *result = new sshBlob();
    result->Append((Byte*)_data, _len);
    result->Autorelease();
    return result;
}

#pragma mark -
#pragma mark sshNameList

namespace sshTypes_Internal {
    class LinkedList
    {
    public:
        LinkedList(LinkedList **start, LinkedList **end)
        {
            _start = start;
            _end = end;
            
            _next = NULL;
            _previous = *_end;
            if (_previous)
                _previous->_next = this;
            else
                *_start = this;
            *_end = this;
        }
        
        ~LinkedList()
        {
            if (_previous)
                _previous->_next = _next;
            if (_next)
                _next->_previous = _previous;
            if (*_start == this)
                *_start = _next;
            if (*_end == this)
                *_end = _previous;
        }
        
        LinkedList* Find(int index)
        {
            LinkedList *start = this;
            while (index && start) {
                start = start->_next;
                index--;
            }
            return start;
        }
        
        int Count(void)
        {
            LinkedList *start = this;
            int count = 0;
            while (start) {
                start = start->_next;
                count++;
            }
            return count;
        }

    private:
        LinkedList **_start, **_end;
    protected:
        LinkedList *_previous, *_next;
    };
    
    class Node : public LinkedList
    {
    public:
        Node(Node **start, Node **end, sshString *item)
        :LinkedList((LinkedList**)start, (LinkedList**)end)
        {
            _item = item;
            _item->AddRef();
        }
        
        ~Node()
        {
            _item->Release();
        }
        
        sshString* Value(void)
        {
            return _item;
        }
        
        Node* Find(int index)
        {
            return (Node*)LinkedList::Find(index);
        }
        
        Node* Find(const sshString *string)
        {
            Node *start = this;
            while (start) {
                if (start->_item->IsEqual(string))
                    return start;
                start = (Node*)start->_next;
            }
            return NULL;
        }

    private:
        sshString *_item;
    };
    
    class Map : public LinkedList
    {
    public:
        Map(Map **start, Map **end, sshString *key, sshObject *value)
        :LinkedList((LinkedList**)start, (LinkedList**)end)
        {
            _key = key;
            _key->AddRef();
            _value = value;
            _value->AddRef();
        }
    
        ~Map()
        {
            _key->Release();
            _value->Release();
        }
        
        Map* Find(const sshString *key)
        {
            Map *start = this;
            while (start) {
                if (start->_key->IsEqual(key))
                    return start;
                start = (Map*)start->_next;
            }
            return NULL;
        }
        
        sshString* Key(void)
        {
            return _key;
        }
        
        sshObject* Value(void)
        {
            return _value;
        }
        
        void SetValue(sshObject *value)
        {
            if (_value == value)
                return;
            _value->Release();
            _value = value;
            _value->AddRef();
        }
        
        sshNameList* AllKeys(void) const
        {
            sshNameList *result = new sshNameList();
            const Map *start = this;
            while (start) {
                result->Add(start->_key);
                start = (Map*)start->_next;
            }
            return result;
        }
        
    private:
        sshString *_key;
        sshObject *_value;
    };
}

sshNameList::sshNameList()
{
    _first = _last = NULL;
}

sshNameList::~sshNameList()
{
    Reset();
}

void sshNameList::Add(sshString *item)
{
    new sshTypes_Internal::Node(&_first, &_last, item);
}

void sshNameList::Remove(int index)
{
    sshTypes_Internal::Node *node = _first->Find(index);
    if (node)
        delete node;
}

void sshNameList::Remove(sshString *item)
{
    sshTypes_Internal::Node *node = _first->Find(item);
    if (node)
        delete node;
}

void sshNameList::Reset(void)
{
    while (_first)
        delete _first;
}

int sshNameList::Count(void) const
{
    return _first->Count();
}

sshString* sshNameList::ItemAt(int index) const
{
    sshTypes_Internal::Node *node = _first->Find(index);
    return node ? node->Value() : NULL;
}

#pragma mark -
#pragma mark sshBlob

sshBlob::sshBlob()
{
    _max = GRAIN;
    _value = new Byte[_max];
    _len = 0;
}

sshBlob::sshBlob(sshString *string)
{
    _max = string->Length();
    _value = new Byte[_max];
    _len = _max;
    memcpy(_value, string->Value(), _len);
}

sshString* sshBlob::AsString(void)
{
    sshString *str = new sshString(this);
    str->Autorelease();
    return str;
}

sshBlob* sshBlob::XorWith(sshBlob *other)
{
    if (_len != other->_len)
        return NULL;
    sshBlob *result = new sshBlob();
    result->Append(_value, _len);
    for (int i = 0; i < _len; i++)
        result->_value[i] ^= other->_value[i];
    result->Autorelease();
    return result;
}

sshBlob::~sshBlob()
{
    delete[] _value;
}

void sshBlob::Reset(void)
{
    _len = 0;
}

void sshBlob::Append(const Byte *bytes, int length)
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

void sshBlob::Strip(int location, int length)
{
    memmove(_value + location, _value + location + length, _len - (location + length));
    _len -= length;
}

const Byte* sshBlob::Value(void) const
{
    return _value;
}

int sshBlob::Length(void) const
{
    return _len;
}

bool sshBlob::Compare(sshBlob *other)
{
    if (_len != other->_len)
        return false;
    if (_len == 0)
        return true;
    return memcmp(_value, other->_value, _len) == 0;
}

#pragma mark -
#pragma mark sshDictionary

sshDictionary::sshDictionary()
{
    _first = _last = NULL;
}

sshDictionary::~sshDictionary()
{
    Reset();
}

void sshDictionary::Set(sshString *key, sshObject *value)
{
    sshTypes_Internal::Map *map = _first->Find(key);
    if (value == NULL) {
        if (map)
            delete map;
    } else {
        if (map)
            map->SetValue(value);
        else
            new sshTypes_Internal::Map(&_first, &_last, key, value);
    }
}

void sshDictionary::Reset(void)
{
    while (_first)
        delete _first;
}

sshObject* sshDictionary::ObjectFor(sshString *key) const
{
    sshTypes_Internal::Map *map = _first->Find(key);
    return map ? map->Value() : NULL;
}

sshNameList* sshDictionary::AllKeys(void) const
{
    return _first->AllKeys();
}

#pragma mark -
#pragma mark sshReader

sshReader::sshReader(const sshBlob *data, int offset)
{
    _cursor = data->Value();
    _length = data->Length();
    
    _cursor += offset;
    _length -= offset;
}

sshReader::sshReader(const sshString *string)
{
    _cursor = (Byte*)string->Value();
    _length = string->Length();
}

Byte sshReader::ReadByte(void)
{
    return *(_cursor++);
}

sshBlob* sshReader::ReadBytes(int length)
{
    sshBlob *blob = new sshBlob();
    blob->Append(_cursor, length);
    _cursor += length;
    _length -= length;
    return blob;
}

bool sshReader::ReadBoolean(void)
{
    return (bool)*(_cursor++);
}

UInt32 sshReader::ReadUInt32(void)
{
    UInt32 value = *(UInt32*)_cursor;
    _cursor += sizeof(UInt32);
    _length -= sizeof(UInt32);
    return Swap32(value);
}

UInt64 sshReader::ReadUInt64(void)
{
    UInt64 value = *(UInt64*)_cursor;
    _cursor += sizeof(UInt64);
    _length -= sizeof(UInt64);
    return Swap64(value);
}

sshString* sshReader::ReadString(void)
{
    UInt32 length = ReadUInt32();
    sshString *result = new sshString();
    result->Append((char*)_cursor, (int)length);
    _cursor += length;
    _length -= length;
    return result;
}

LargeNumber* sshReader::ReadMPInt(void)
{
    sshString *value = ReadString();
    LargeNumber *result;
    if (value->Length() == 0)
        result = new LargeNumber(0);
    else
        result = new LargeNumber(value->Value(), value->Length());
    result->Autorelease();
    return result;
}

static void AddEntry(sshNameList *list, const char *s, int l)
{
    if (l <= 0)
        return;
    sshString *out = new sshString();
    out->Append(s, l);
    list->Add(out);
    out->Release();
}

sshNameList* sshReader::ReadNameList(void)
{
    sshString *string = ReadString();
    sshNameList *list = new sshNameList();
    const char *s = string->Value();
    int j = string->Length();
    int base = 0;
    for (int i = 0; i < j; i++) {
        if (s[i] == ',') {
            AddEntry(list, s + base, i - base);
            base = i + 1;
        }
    }
    if (base < j)
        AddEntry(list, s + base, j - base);
    string->Release();
    return list;
}

void sshReader::SkipBytes(int length)
{
    _cursor += length;
    _length -= length;
}

sshWriter::sshWriter(sshBlob *output)
{
    _blob = output;
    _blob->AddRef();
}

sshWriter::~sshWriter()
{
    _blob->Release();
}

void sshWriter::Write(Byte byte)
{
    _blob->Append(&byte, 1);
}

void sshWriter::Write(sshBlob *bytes)
{
    _blob->Append(bytes->Value(), bytes->Length());
}

void sshWriter::Write(bool boolean)
{
    Write(Byte(boolean ? 1 : 0));
}

void sshWriter::Write(UInt32 value)
{
    UInt32 raw = Swap32(value);
    _blob->Append((Byte*)&raw, sizeof(raw));
}

void sshWriter::Write(UInt64 value)
{
    UInt64 raw = Swap64(value);
    _blob->Append((Byte*)&raw, sizeof(raw));
}

void sshWriter::Write(sshString *string)
{
    Write((UInt32)string->Length());
    _blob->Append((Byte*)string->Value(), string->Length());
}

void sshWriter::Write(LargeNumber *value)
{
    sshBlob *blob = value->Data();
    Write((UInt32)blob->Length());
    _blob->Append(blob->Value(), blob->Length());
}

void sshWriter::Write(sshNameList *nameList)
{
    sshString *value = new sshString();
    const char c = ',';
    for (int i = 0; i < nameList->Count(); i++) {
        if (i)
            value->Append(&c, 1);
        value->Append(nameList->ItemAt(i));
    }
    Write(value);
    value->Release();
}
