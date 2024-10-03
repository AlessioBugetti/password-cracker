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

/**
 * @brief Decryption strategy using sequential processing.
 */
class SequentialDecryption : public DecryptionStrategy
{
  public:
    /**
     * @brief Default constructor.
     */
    SequentialDecryption() = default;

    /**
     * @brief Constructor with a list of passwords.
     * @param passwords List of passwords to use for decryption
     */
    SequentialDecryption(std::vector<std::string> passwords);

    /**
     * @brief Destructor.
     */
    ~SequentialDecryption() override = default;

    /**
     * @brief Decrypts an encrypted password using sequential processing.
     *
     * This function utilizes the `crypt_r` function from the `<crypt.h>`
     * header on Linux systems and the `OpenSSL::DES_fcrypt()` function on macOS systems to
     * decrypt the provided encrypted password.
     *
     * @param encryptedPassword The encrypted password to decrypt
     * @return A tuple containing a boolean indicating success, the decrypted password, and the time
     * taken in milliseconds
     */
    std::tuple<bool, std::string, double> Decrypt(
        const std::string& encryptedPassword) const override;
};

} // namespace passwordcracker

#endif // SEQUENTIAL_DECRYPTION_H
