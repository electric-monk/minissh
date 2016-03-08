//
//  AES.h
//  minissh
//
//  Created by Colin David Munro on 7/02/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#ifndef __minissh__AES__
#define __minissh__AES__

#include "Encryption.h"

class AES : public Encryption
{
public:
    AES(sshBlob *key);

    sshBlob* Encrypt(sshBlob *data);
    sshBlob* Decrypt(sshBlob *data);
    
protected:
    ~AES();
    
private:
    int _rounds;
    sshBlob *_expandedKey;
};

#endif /* defined(__minissh__AES__) */
