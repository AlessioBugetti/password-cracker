/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

#include "sequential-decryption.h"

#include <crypt.h>
#include <omp.h>

namespace passwordcracker
{

SequentialDecryption::SequentialDecryption(std::vector<std::string> passwords)
    : DecryptionStrategy(passwords)
{
}

std::tuple<bool, std::string, double>
SequentialDecryption::Decrypt(const std::string& encryptedPassword) const
{
    const std::vector<std::string>& passwords = GetPasswords();
    std::string salt = encryptedPassword.substr(0, 2);
    bool found = false;
    std::string decryptedPassword = "";
    double startTime = omp_get_wtime();
    for (auto tmpPassword : passwords)
    {
        std::string encryptedTmpPassword = crypt(tmpPassword.c_str(), salt.c_str());
        if (encryptedTmpPassword == encryptedPassword)
        {
            found = true;
            decryptedPassword = tmpPassword;
            break;
        }
    }
    double endTime = omp_get_wtime();
    return {found, decryptedPassword, endTime - startTime};
}

} // namespace passwordcracker