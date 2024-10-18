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
#include <omp.h>

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

std::tuple<bool, std::string, double>
ParallelOmpDecryptor::Decrypt(const std::string& encryptedPassword) const
{
    const std::vector<std::string>& passwords = GetPasswords();
    int numPasswords = passwords.size();
    std::string salt = encryptedPassword.substr(0, 2);

#ifdef __linux__
    struct crypt_data data;
    data.initialized = 0;
#else
    char data[14] = {0};
#endif

    int index = -1;

    int numThreads = GetNumThreads();

    double startTime = omp_get_wtime();

#pragma omp parallel for default(none) shared(index, passwords)                                    \
    firstprivate(encryptedPassword, numPasswords, salt, data) num_threads(numThreads)
    for (int i = 0; i < numPasswords; ++i)
    {
#pragma omp cancellation point for

#ifdef __linux__
        std::string encryptedTmpPassword = crypt_r(passwords[i].c_str(), salt.c_str(), &data);
#else
        DES_fcrypt(passwords[i].c_str(), salt.c_str(), data);
        std::string encryptedTmpPassword(data);
#endif

        if (encryptedTmpPassword == encryptedPassword)
        {
#pragma omp atomic write release
            index = i;
#pragma omp cancel for
        }
    }

    double endTime = omp_get_wtime();

    if (index == -1)
    {
        return {false, "", endTime - startTime};
    }
    else
    {
        return {true, passwords[index], (endTime - startTime) * 1000};
    }
}

} // namespace passwordcracker
