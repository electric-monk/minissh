//
//  TestUtils.cpp
//  minissh
//
//  Created by Colin David Munro on 3/08/2020.
//  Copyright © 2020 MICE Software. All rights reserved.
//

#include "TestUtils.h"
#include "SSH_AES.h"
#include "DiffieHellman.h"
#include "SSH_RSA.h"
#include "SSH_HMAC.h"

void ConfigureSSH(minissh::Transport::Configuration& sshConfiguration)
{
    minissh::Algorithms::DiffieHellman::Group14::Factory::Add(sshConfiguration.supportedKeyExchanges);
    minissh::Algorithms::DiffieHellman::Group1::Factory::Add(sshConfiguration.supportedKeyExchanges);
    minissh::Algoriths::SSH_RSA::Factory::Add(sshConfiguration.serverHostKeyAlgorithms);
    minissh::Algorithm::AES128_CBC::Factory::Add(sshConfiguration.encryptionAlgorithms_clientToServer);
    minissh::Algorithm::AES128_CBC::Factory::Add(sshConfiguration.encryptionAlgorithms_serverToClient);
    //minissh::Algorithm::AES192_CBC::Factory::Add(sshConfiguration.encryptionAlgorithms_clientToServer);
    //minissh::Algorithm::AES192_CBC::Factory::Add(sshConfiguration.encryptionAlgorithms_serverToClient);
    //minissh::Algorithm::AES256_CBC::Factory::Add(sshConfiguration.encryptionAlgorithms_clientToServer);
    //minissh::Algorithm::AES256_CBC::Factory::Add(sshConfiguration.encryptionAlgorithms_serverToClient);
    minissh::Algorithm::AES128_CTR::Factory::Add(sshConfiguration.encryptionAlgorithms_clientToServer);
    minissh::Algorithm::AES128_CTR::Factory::Add(sshConfiguration.encryptionAlgorithms_serverToClient);
    //minissh::Algorithm::AES192_CTR::Factory::Add(sshConfiguration.encryptionAlgorithms_clientToServer);
    //minissh::Algorithm::AES192_CTR::Factory::Add(sshConfiguration.encryptionAlgorithms_serverToClient);
    //minissh::Algorithm::AES256_CTR::Factory::Add(sshConfiguration.encryptionAlgorithms_clientToServer);
    //minissh::Algorithm::AES256_CTR::Factory::Add(sshConfiguration.encryptionAlgorithms_serverToClient);
    minissh::Algorithm::HMAC_SHA1::Factory::Add(sshConfiguration.macAlgorithms_clientToServer);
    minissh::Algorithm::HMAC_SHA1::Factory::Add(sshConfiguration.macAlgorithms_serverToClient);
    minissh::Transport::NoneCompression::Factory::Add(sshConfiguration.compressionAlgorithms_clientToServer);
    minissh::Transport::NoneCompression::Factory::Add(sshConfiguration.compressionAlgorithms_serverToClient);
}
