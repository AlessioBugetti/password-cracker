/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

#include "sequential-decryptor.h"

#ifdef __linux__
#include <crypt.h>
#else
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/des.h>
#endif
#include <omp.h>

namespace passwordcracker
{

SequentialDecryptor::SequentialDecryptor(std::vector<std::string> passwords)
    : Decryptor(passwords)
{
}

std::tuple<bool, std::string, double>
SequentialDecryptor::Decrypt(const std::string& encryptedPassword) const
{
    const std::vector<std::string>& passwords = GetPasswords();
    const int numPasswords = passwords.size();
    std::string salt = encryptedPassword.substr(0, 2);

#ifdef __linux__
    struct crypt_data data;
    data.initialized = 0;
#else
    char data[14] = {0};
#endif

    double startTime = omp_get_wtime();
    for (int index = 0; index < numPasswords; index++)
    {
#ifdef __linux__
        std::string encryptedTmpPassword = crypt_r(passwords[index].c_str(), salt.c_str(), &data);
#else
        std::string encryptedTmpPassword = DES_fcrypt(passwords[index].c_str(), salt.c_str(), data);
#endif
        if (encryptedTmpPassword == encryptedPassword)
        {
            return {true, passwords[index], (omp_get_wtime() - startTime) * 1000};
        }
    }
    return {false, "", (omp_get_wtime() - startTime) * 1000};
}

} // namespace passwordcracker
