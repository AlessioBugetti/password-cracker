/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

#include "parallel-omp-decryption.h"

#include <crypt.h>
#include <iostream>
#include <omp.h>

namespace passwordcracker
{

ParallelOmpDecryption::ParallelOmpDecryption(int numThreads)
    : numThreads(numThreads)
{
}

ParallelOmpDecryption::ParallelOmpDecryption(std::vector<std::string> passwords)
    : DecryptionStrategy(passwords)
{
}

ParallelOmpDecryption::ParallelOmpDecryption(int numThreads, std::vector<std::string> passwords)
    : DecryptionStrategy(passwords),
      numThreads(numThreads)
{
}

int
ParallelOmpDecryption::GetNumThreads() const
{
    return numThreads;
}

void
ParallelOmpDecryption::SetNumThreads(int numThreads)
{
    this->numThreads = numThreads;
}

std::tuple<bool, std::string, double>
ParallelOmpDecryption::Decrypt(const std::string& encryptedPassword) const
{
    volatile bool found = false;
    std::string decryptedPassword = "";

    const std::string& salt = encryptedPassword.substr(0, 2);
    const std::vector<std::string>& passwords = GetPasswords();
    size_t numPasswords = passwords.size();

    omp_lock_t mtx;
    omp_init_lock(&mtx);
    double startTime = omp_get_wtime();

#pragma omp parallel num_threads(numThreads) default(none)                                         \
    shared(encryptedPassword, mtx, salt, found, passwords, decryptedPassword)
    {
        bool local_found = false;
        std::string local_decryptedPassword;

        struct crypt_data data;
        data.initialized = 0;

        int threadNum = omp_get_thread_num();
        int totalThreads = omp_get_num_threads();

        int itemsPerThread = static_cast<int>(passwords.size() / totalThreads);
        int threadStartIdx = threadNum * itemsPerThread;
        int threadEndIdx =
            std::min(threadStartIdx + itemsPerThread, static_cast<int>(passwords.size())) - 1;

        for (int i = threadStartIdx; i <= threadEndIdx; ++i)
        {
            if (found)
            {
                break;
            }

            std::string encryptedTmpPassword = crypt_r(passwords[i].c_str(), salt.c_str(), &data);

            if (encryptedTmpPassword == encryptedPassword)
            {
                local_found = true;
                local_decryptedPassword = passwords[i];
                break;
            }
        }

        if (local_found)
        {
            omp_set_lock(&mtx);
            if (!found)
            {
                found = true;
                decryptedPassword = local_decryptedPassword;
            }
            omp_unset_lock(&mtx);
        }
    }

    double endTime = omp_get_wtime();

    omp_destroy_lock(&mtx);

    return {found, decryptedPassword, endTime - startTime};
}

} // namespace passwordcracker