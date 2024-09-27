#include "decryption-strategy.h"

#include <fstream>

namespace passwordcracker
{
std::vector<std::string>
DecryptionStrategy::getPasswords() const
{
    return passwords;
}

void
DecryptionStrategy::loadPasswords(const std::string& filepath)
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