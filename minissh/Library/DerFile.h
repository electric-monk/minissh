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
    
/**
 * Callback for streaming parsing DER data.
 */
class ICallback
{
public:
    virtual ~ICallback() = default;
    
    virtual void StartSequence(void) {}
    virtual void EndSequence(void) {}

    virtual void StartSet(void) {}
    virtual void EndSet(void) {}

    virtual void ReadInteger(Maths::BigNumber i) {}
    
    virtual void ReadObjectIdentifier(const std::vector<UInt32>& id) {}
    
    virtual void ReadNull(void) {}
    
    virtual void Unknown(Byte type, Types::Blob data) = 0;
};
 
/**
 * Streaming parser for DER binary data.
 */
void Load(minissh::Types::Blob input, ICallback& callbacks);
    
}
    
namespace Writer {
    
/**
 * Interface for a DER data type, providing a 'save' method.
 */
class IBase
{
public:
    virtual ~IBase() = default;
    
    virtual Types::Blob Save(void) = 0;
};

/**
 * Base implementation for a DER container.
 */
class Container : public IBase
{
protected:
    const Byte _type;
    Container(Byte type);
public:
    Types::Blob Save(void) override;
    
    std::vector<std::shared_ptr<IBase>> components;
};
    
/**
 * Class representing a SEQUENCE.
 */
class Sequence : public Container
{
public:
    Sequence();
};
 
/**
 * Class representing a SET.
 */
class Set : public Container
{
public:
    Set();
};

/**
 * Class representing an INTEGER.
 */
class Integer : public IBase
{
public:
    Integer(){}
    Integer(Maths::BigNumber init):value(init){}
    Types::Blob Save(void) override;
    Maths::BigNumber value;
};

/**
 * Class representing an OBJECT IDENTIFIER.
 */
class ObjectIdentifier : public IBase
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
  
/**
 * Class representing a NULL.
 */
class Null : public IBase
{
public:
    Null();
    Types::Blob Save(void) override;
};
    
}

} // namespace minissh::Files::DER
