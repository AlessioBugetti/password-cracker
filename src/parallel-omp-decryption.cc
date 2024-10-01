/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

#include "parallel-omp-decryption.h"

#include <crypt.h>
#include <omp.h>

namespace passwordcracker
{

ParallelOmpDecryption::ParallelOmpDecryption()
    : numThreads(omp_get_max_threads())
{
}

ParallelOmpDecryption::ParallelOmpDecryption(int numThreads)
    : numThreads(numThreads)
{
}

ParallelOmpDecryption::ParallelOmpDecryption(std::vector<std::string> passwords)
    : DecryptionStrategy(passwords),
      numThreads(omp_get_max_threads())
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
    std::string salt = encryptedPassword.substr(0, 2);
    const std::vector<std::string>& passwords = GetPasswords();
    int numPasswords = passwords.size();

    omp_set_num_threads(numThreads);
    omp_set_dynamic(0);

    int index = -1;

    double startTime = omp_get_wtime();

#pragma omp parallel default(none) shared(index, passwords, encryptedPassword, salt, numPasswords)
    {
        struct crypt_data data;
        data.initialized = 0;
        int tmp_index;

#pragma omp for
        for (int i = 0; i < numPasswords; ++i)
        {
#pragma omp atomic read acquire
            tmp_index = index;
            if (tmp_index == -1)
            {
                std::string encryptedTmpPassword =
                    crypt_r(passwords[i].c_str(), salt.c_str(), &data);

                if (encryptedTmpPassword == encryptedPassword)
                {
#pragma omp atomic write release
                    index = i;
                }
            }
        }
    }

    double endTime = omp_get_wtime();

    if (index == -1)
    {
        return {false, "", endTime - startTime};
    }
    else
    {
        return {true, passwords[index], endTime - startTime};
    }
}

} // namespace passwordcracker