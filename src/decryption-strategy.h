/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

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

    DecryptionStrategy(std::vector<std::string> passwords);

    virtual ~DecryptionStrategy() = default;

    std::vector<std::string> GetPasswords() const;

    void LoadPasswords(const std::string& filepath);

    virtual std::tuple<bool, std::string, double> Decrypt(
        const std::string& encryptedPassword) const = 0;

  private:
    std::vector<std::string> passwords;
};

} // namespace passwordcracker

#endif // DECRYPTION_STRATEGY_H