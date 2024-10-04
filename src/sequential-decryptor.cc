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
    std::string salt = encryptedPassword.substr(0, 2);
    bool found = false;
    std::string decryptedPassword = "";
    auto startTime = std::chrono::high_resolution_clock::now();
#ifdef __linux__
    struct crypt_data data;
    data.initialized = 0;
#else
    char data[14] = {0};
#endif
    for (auto tmpPassword : passwords)
    {
#ifdef __linux__
        std::string encryptedTmpPassword = crypt_r(tmpPassword.c_str(), salt.c_str(), &data);
#else
        std::string encryptedTmpPassword = DES_fcrypt(tmpPassword.c_str(), salt.c_str(), data);
#endif
        if (encryptedTmpPassword == encryptedPassword)
        {
            found = true;
            decryptedPassword = tmpPassword;
            break;
        }
    }
    auto endTime = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = endTime - startTime;
    return {found, decryptedPassword, duration.count()};
}

} // namespace passwordcracker
