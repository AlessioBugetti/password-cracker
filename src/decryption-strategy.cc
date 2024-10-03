/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

#include "decryption-strategy.h"

#include <fstream>

namespace passwordcracker
{

DecryptionStrategy::DecryptionStrategy(std::vector<std::string> passwords)
    : passwords(passwords)
{
}

std::vector<std::string>
DecryptionStrategy::GetPasswords() const
{
    return passwords;
}

void
DecryptionStrategy::LoadPasswords(const std::string& filepath)
{
    std::ifstream file(filepath);
    if (!file.is_open())
    {
        throw std::runtime_error("Could not open file: " + filepath);
    }

    std::string password;
    while (std::getline(file, password))
    {
        passwords.push_back(password);
    }
}

} // namespace passwordcracker
