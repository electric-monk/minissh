//
//  hmac.h
//  minissh
//
//  Created by Colin David Munro on 9/02/2016.
//  Copyright (c) 2016 MICE Software. All rights reserved.
//

#ifndef __minissh__hmac__
#define __minissh__hmac__

class HashType;
class sshBlob;

sshBlob* HMAC(HashType *hash, sshBlob *key, sshBlob *text);

#endif /* defined(__minissh__hmac__) */
