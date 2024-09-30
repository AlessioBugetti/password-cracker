/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

#ifndef SEQUENTIAL_DECRYPTION_H
#define SEQUENTIAL_DECRYPTION_H

#include "decryption-strategy.h"

namespace passwordcracker
{

class SequentialDecryption : public DecryptionStrategy
{
  public:
    SequentialDecryption() = default;

    SequentialDecryption(std::vector<std::string> passwords);

    ~SequentialDecryption() = default;

    std::tuple<bool, std::string> Decrypt(const std::string& encryptedPassword) const override;
};

} // namespace passwordcracker

#endif // SEQUENTIAL_DECRYPTION_H