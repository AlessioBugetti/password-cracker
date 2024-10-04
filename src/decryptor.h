/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

#ifndef DECRYPTOR_H
#define DECRYPTOR_H

#include <string>
#include <vector>

namespace passwordcracker
{

/**
 * @brief Abstract base class for decryption strategies.
 *
 * This class provides the interface for different decryption strategies.
 */
class Decryptor
{
  public:
    /**
     * @brief Default constructor.
     */
    Decryptor() = default;

    /**
     * @brief Constructor with a list of passwords.
     * @param passwords List of passwords to use for decryption
     */
    Decryptor(std::vector<std::string> passwords);

    /**
     * @brief Virtual destructor.
     */
    virtual ~Decryptor() = default;

    /**
     * @brief Gets the list of passwords.
     * @return List of passwords to use for decryption
     */
    std::vector<std::string> GetPasswords() const;

    /**
     * @brief Loads passwords from a file.
     * @param filepath Path to the file containing passwords
     */
    void LoadPasswords(const std::string& filepath);

    /**
     * @brief Decrypts an encrypted password.
     * @param encryptedPassword The encrypted password to decrypt
     * @return A tuple containing a boolean indicating success, the decrypted password, and the time
     * taken in milliseconds
     */
    virtual std::tuple<bool, std::string, double> Decrypt(
        const std::string& encryptedPassword) const = 0;

  private:
    std::vector<std::string> passwords; ///< List of passwords.
};

} // namespace passwordcracker

#endif // DECRYPTOR_H
