/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

#ifndef SEQUENTIAL_DECRYPTOR_H
#define SEQUENTIAL_DECRYPTOR_H

#include "decryptor.h"

namespace passwordcracker
{

/**
 * @brief Decryptor using sequential processing.
 */
class SequentialDecryptor : public Decryptor
{
  public:
    /**
     * @brief Default constructor.
     */
    SequentialDecryptor() = default;

    /**
     * @brief Constructor with a list of passwords.
     * @param passwords List of passwords to use for decryption
     */
    SequentialDecryptor(std::vector<std::string> passwords);

    /**
     * @brief Destructor.
     */
    ~SequentialDecryptor() override = default;

    /**
     * @brief Decrypts an encrypted password using sequential processing.
     *
     * This function utilizes the `crypt_r` function from the `<crypt.h>`
     * header on Linux systems and the `OpenSSL::DES_fcrypt()` function on macOS systems to
     * decrypt the provided encrypted password.
     *
     * @param encryptedPassword The encrypted password to decrypt
     * @return A tuple containing a boolean indicating success and the decrypted password if the
     * boolean is true, otherwise an empty string
     */
    std::tuple<bool, std::string> Decrypt(const std::string& encryptedPassword) const override;
};

} // namespace passwordcracker

#endif // SEQUENTIAL_DECRYPTOR_H
