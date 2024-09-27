#ifndef SEQUENTIAL_DECRYPTION_H
#define SEQUENTIAL_DECRYPTION_H

#include "decryption-strategy.h"

namespace passwordcracker
{

class SequentialDecryption : public DecryptionStrategy
{
  public:
    SequentialDecryption() = default;
    ~SequentialDecryption() = default;

    std::tuple<bool, std::string> decrypt(const std::string& encryptedPassword) const override;
};

} // namespace passwordcracker

#endif // SEQUENTIAL_DECRYPTION_H