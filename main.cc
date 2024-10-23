/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

#include "parallel-omp-decryptor.h"
#include "sequential-decryptor.h"
#include <iostream>
#include <memory>
#include <omp.h>
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
    double startTime = omp_get_wtime();
    auto [decrypted, decryptedPassword] = decryptionStrategy->Decrypt(encryptedPassword);
    double endTime = omp_get_wtime();
    std::cout << "Time: " << (endTime - startTime) * 1000 << " ms" << std::endl;
    std::cout << "Decrypted password: " << decryptedPassword << std::endl;
    return 0;
}
