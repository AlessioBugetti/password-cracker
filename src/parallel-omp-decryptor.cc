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
    : numThreads(omp_get_max_threads())
{
}

ParallelOmpDecryptor::ParallelOmpDecryptor(int numThreads)
    : numThreads(numThreads)
{
}

ParallelOmpDecryptor::ParallelOmpDecryptor(std::vector<std::string> passwords)
    : Decryptor(passwords),
      numThreads(omp_get_max_threads())
{
}

ParallelOmpDecryptor::ParallelOmpDecryptor(int numThreads, std::vector<std::string> passwords)
    : Decryptor(passwords),
      numThreads(numThreads)
{
}

int
ParallelOmpDecryptor::GetNumThreads() const
{
    return numThreads;
}

void
ParallelOmpDecryptor::SetNumThreads(int numThreads)
{
    this->numThreads = numThreads;
}

std::tuple<bool, std::string, double>
ParallelOmpDecryptor::Decrypt(const std::string& encryptedPassword) const
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
#ifdef __linux__
        struct crypt_data data;
        data.initialized = 0;
#else
        char data[14] = {0};
#endif
        int tmp_index;
#pragma omp for
        for (int i = 0; i < numPasswords; ++i)
        {
#pragma omp atomic read acquire
            tmp_index = index;
            if (tmp_index == -1)
            {
#ifdef __linux__
                std::string encryptedTmpPassword =
                    crypt_r(passwords[i].c_str(), salt.c_str(), &data);
#else
                DES_fcrypt(passwords[i].c_str(), salt.c_str(), data);
                std::string encryptedTmpPassword(data);
#endif

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
