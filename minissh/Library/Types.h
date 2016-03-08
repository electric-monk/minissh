//
//  Types.h
//  minissh
//
//  Created by Colin David Munro on 10/01/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#ifndef minissh_Types_h
#define minissh_Types_h

//#define DEBUG_KEX
//#define DEBUG_LOG_TRANSFER_INFO
//#define DEBUG_LOG_STATE_INFO

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

typedef unsigned char Byte;
typedef unsigned short UInt16;
typedef unsigned int UInt32;
typedef unsigned long long UInt64;

#ifdef __cplusplus

class LargeNumber;
class sshBlob;

namespace sshTypes_Internal {
    class Node;
    class Map;
}

class sshObject
{
public:
    class Releaser
    {
    public:
        Releaser();
        ~Releaser();
        
        void Flush(void);
    private:
        void *_data, *_other;
        friend sshObject;
    };
    
    sshObject();
    
    void AddRef(void);
    void Release(void);
    
    void Autorelease(void);
    
protected:
    virtual ~sshObject() {}
    
private:
    UInt32 _refCount;
};

class sshString : public sshObject
{
public:
    sshString();
    sshString(sshBlob *blob);
    
    const char* Value(void) const;  // Not null terminated
    int Length(void) const;
    bool IsEqual(const sshString *other) const;
    bool IsEqual(const char *other) const;
    
    void Reset(void);
    void AppendFormat(const char *format, ...);
    void Append(const char *bytes, int length);
    void Append(sshString *string);
    
    void DebugDump(void);
    
    sshBlob* AsBlob(void);
    
protected:
    ~sshString();
    
private:
    void CheckSize(int length);
    
    char *_data;
    int _len, _max;
};

class sshNameList : public sshObject
{
public:
    sshNameList();
    
    void Add(sshString *item);
    void Remove(int index);
    void Remove(sshString *item);
    void Reset(void);
    
    int Count(void) const;
    sshString* ItemAt(int index) const;
    
protected:
    ~sshNameList();
    
private:
    sshTypes_Internal::Node *_first, *_last;
};

class sshBlob : public sshObject
{
public:
    sshBlob();
    sshBlob(sshString *string);
    
    void Reset(void);
    void Append(const Byte *bytes, int length);
    void Strip(int location, int length);
    
    const Byte* Value(void) const;
    int Length(void) const;
    
    bool Compare(sshBlob *other);
    
    sshString* AsString(void);
    
    sshBlob* XorWith(sshBlob *other);
    
    void DebugDump(void);
    
protected:
    ~sshBlob();
    
private:
    Byte *_value;
    int _len, _max;
};

class sshDictionary : public sshObject
{
public:
    sshDictionary();
    
    void Set(sshString *key, sshObject *value);
    sshObject* ObjectFor(sshString *key) const;
    void Reset(void);
    
    sshNameList* AllKeys(void) const;
    
protected:
    ~sshDictionary();
    
private:
    sshTypes_Internal::Map *_first, *_last;
};

class sshReader
{
public:
    sshReader(const sshBlob *data, int offset = 0);
    sshReader(const sshString *string);
    
    Byte ReadByte(void);
    sshBlob* ReadBytes(int length);
    bool ReadBoolean(void);
    UInt32 ReadUInt32(void);
    UInt64 ReadUInt64(void);
    sshString* ReadString(void);
    LargeNumber* ReadMPInt(void);
    sshNameList* ReadNameList(void);
    void SkipBytes(int length);
    
    int Remaining(void) { return _length; }
    
private:
    const Byte *_cursor;
    int _length;
};

class sshWriter
{
public:
    sshWriter(sshBlob *output);
    ~sshWriter();
    
    void Write(Byte byte);
    void Write(sshBlob *bytes);
    void Write(bool boolean);
    void Write(UInt32 value);
    void Write(UInt64 value);
    void Write(sshString *string);
    void Write(LargeNumber *value);
    void Write(sshNameList *nameList);
    
private:
    sshBlob *_blob;
};

#endif
#endif
