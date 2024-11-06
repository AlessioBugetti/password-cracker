/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

#include "parallel-omp-decryptor.h"

#ifdef __linux__
#include <crypt.h>
#else
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/des.h>
#endif

namespace passwordcracker
{

ParallelOmpDecryptor::ParallelOmpDecryptor()
    : ParallelDecryptor()
{
}

ParallelOmpDecryptor::ParallelOmpDecryptor(int numThreads)
    : ParallelDecryptor(numThreads)
{
}

ParallelOmpDecryptor::ParallelOmpDecryptor(std::vector<std::string> passwords)
    : ParallelDecryptor(passwords)
{
}

ParallelOmpDecryptor::ParallelOmpDecryptor(int numThreads, std::vector<std::string> passwords)
    : ParallelDecryptor(numThreads, passwords)
{
}

std::tuple<bool, std::string>
ParallelOmpDecryptor::Decrypt(const std::string& encryptedPassword) const
{
    const std::vector<std::string>& passwords = GetPasswords();
    int numPasswords = passwords.size();
    std::string salt = encryptedPassword.substr(0, 2);

    int index = -1;

    int numThreads = GetNumThreads();

#pragma omp parallel default(none) shared(index, passwords)                                        \
    firstprivate(encryptedPassword, numPasswords, salt) num_threads(numThreads)
    {
#ifdef __linux__
        struct crypt_data data;
        data.initialized = 0;
#else
        char data[14] = {0};
#endif
#pragma omp for
        for (int i = 0; i < numPasswords; i++)
        {
#ifdef __linux__
            std::string encryptedTmpPassword = crypt_r(passwords[i].c_str(), salt.c_str(), &data);
#else
            std::string encryptedTmpPassword = DES_fcrypt(passwords[i].c_str(), salt.c_str(), data);
#endif

            if (encryptedTmpPassword == encryptedPassword)
            {
#pragma omp atomic write
                index = i;
#pragma omp cancel for
            }
#pragma omp cancellation point for
        }
    }

    if (index == -1)
    {
        return {false, ""};
    }
    else
    {
        return {true, passwords[index]};
    }
}

} // namespace passwordcracker
