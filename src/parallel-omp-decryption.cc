/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

#include "parallel-omp-decryption.h"

#include <iostream>
#include <unistd.h>

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

std::tuple<bool, std::string>
ParallelOmpDecryption::Decrypt(const std::string& encryptedPassword) const
{
    bool found = false;
    std::string decryptedPassword;

    const std::string& salt = encryptedPassword.substr(0, 2);
    const std::vector<std::string>& passwords = GetPasswords();

#pragma omp parallel for num_threads(numThreads) shared(found, decryptedPassword)
    for (size_t i = 0; i < passwords.size(); ++i)
    {
        if (found)
            continue;

        const std::string& tmpPassword = passwords[i];
        const std::string& encryptedTmpPassword = crypt(tmpPassword.c_str(), salt.c_str());

        if (encryptedTmpPassword == encryptedPassword)
        {
#pragma omp critical
            {
                if (!found)
                {
                    found = true;
                    decryptedPassword = tmpPassword;
                }
            }
        }
    }

    return {found, decryptedPassword};
}

} // namespace passwordcracker