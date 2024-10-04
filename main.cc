/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

#include "parallel-omp-decryptor.h"
#include "sequential-decryptor.h"
#include <iostream>
#include <memory>
#include <parallel-pthread-decryptor.h>
#include <unistd.h>

using namespace passwordcracker;

int
main(int argc, char** argv)
{
    std::string inputFile = "data/rockyou.txt";

    std::string password = "sully123";
    std::string salt = "pc";

    auto decryptionStrategy = std::make_unique<ParallelPThreadDecryptor>(4);
    decryptionStrategy->LoadPasswords(inputFile);
    std::string encryptedPassword = crypt(password.c_str(), salt.c_str());
    auto [decrypted, decryptedPassword, time] = decryptionStrategy->Decrypt(encryptedPassword);
    std::cout << "Time: " << time << " ms" << std::endl;
    std::cout << "Decrypted password: " << decryptedPassword << std::endl;
    return 0;
}
