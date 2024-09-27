#include "sequential-decryption.h"

#include <iostream>
#include <unistd.h>

namespace passwordcracker
{

std::tuple<bool, std::string>
SequentialDecryption::decrypt(const std::string& encryptedPassword) const
{
    const std::vector<std::string>& passwords = getPasswords();
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