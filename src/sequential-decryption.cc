/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

#include "sequential-decryption.h"

#include <iostream>
#include <unistd.h>

namespace passwordcracker
{

SequentialDecryption::SequentialDecryption(std::vector<std::string> passwords)
    : DecryptionStrategy(passwords)
{
}

std::tuple<bool, std::string>
SequentialDecryption::Decrypt(const std::string& encryptedPassword) const
{
    const std::vector<std::string>& passwords = GetPasswords();
    if (passwords.empty())
    {
        throw std::runtime_error("No passwords loaded");
    }
    std::string salt = encryptedPassword.substr(0, 2);
    for (const auto& tmpPassword : passwords)
    {
        std::string encryptedTmpPassword = crypt(tmpPassword.c_str(), salt.c_str());
        if (encryptedTmpPassword == encryptedPassword)
        {
            return {true, tmpPassword};
        }
    }
    return {false, ""};
}

} // namespace passwordcracker