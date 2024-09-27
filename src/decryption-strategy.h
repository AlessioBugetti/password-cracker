#ifndef DECRYPTION_STRATEGY_H
#define DECRYPTION_STRATEGY_H

#include <string>
#include <vector>

namespace passwordcracker
{

class DecryptionStrategy
{
  public:
    DecryptionStrategy() = default;

    std::vector<std::string> getPasswords() const;

    void loadPasswords(const std::string& filepath);

    virtual std::tuple<bool, std::string> decrypt(const std::string& encryptedPassword) const = 0;

  private:
    std::vector<std::string> passwords;
};

} // namespace passwordcracker

#endif // DECRYPTION_STRATEGY_H