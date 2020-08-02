//
//  DerFile.h
//  libminissh
//
//  Created by Colin David Munro on 16/06/2020.
//  Copyright © 2020 MICE Software. All rights reserved.
//

#pragma once

#include "Types.h"

namespace minissh::Files::DER {

namespace Reader {
    
class Callback
{
public:
    virtual ~Callback() = default;
    
    virtual void StartSequence(void) {}
    virtual void EndSequence(void) {}

    virtual void StartSet(void) {}
    virtual void EndSet(void) {}

    virtual void ReadInteger(Maths::BigNumber i) {}
    
    virtual void ReadObjectIdentifier(const std::vector<UInt32>& id) {}
    
    virtual void ReadNull(void) {}
    
    virtual void Unknown(Byte type, Types::Blob data) = 0;
};
 
void Load(minissh::Types::Blob input, Callback& callbacks);
    
}
    
namespace Writer {
    
class Base
{
public:
    virtual ~Base() = default;
    
    virtual Types::Blob Save(void) = 0;
};

class Container : public Base
{
protected:
    const Byte _type;
    Container(Byte type);
public:
    Types::Blob Save(void) override;
    
    std::vector<std::shared_ptr<Base>> components;
};
    
class Sequence : public Container
{
public:
    Sequence();
};
 
class Set : public Container
{
public:
    Set();
};

class Integer : public Base
{
public:
    Integer(){}
    Integer(Maths::BigNumber init):value(init){}
    Types::Blob Save(void) override;
    Maths::BigNumber value;
};

class ObjectIdentifier : public Base
{
public:
    ObjectIdentifier(){}
    template<typename X>
    ObjectIdentifier(X iter_begin, X iter_end)
    {
        components.insert(components.begin(), iter_begin, iter_end);
    }
    Types::Blob Save(void) override;
    std::vector<UInt32> components;
};
    
class Null : public Base
{
public:
    Null();
    Types::Blob Save(void) override;
};
    
}

} // namespace minissh::Files::DER
