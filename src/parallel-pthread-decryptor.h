/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

#ifndef PARALLEL_PTHREAD_DECRYPTOR_H
#define PARALLEL_PTHREAD_DECRYPTOR_H

#include "parallel-decryptor.h"

namespace passwordcracker
{

/**
 * @brief Decryptor using pthreads for parallel processing.
 */
class ParallelPThreadDecryptor : public ParallelDecryptor
{
  public:
    /**
     * @brief Default constructor.
     */
    ParallelPThreadDecryptor();

    /**
     * @brief Constructor with a specified number of threads.
     * @param numThreads Number of threads to use for decryption
     */
    ParallelPThreadDecryptor(int numThreads);

    /**
     * @brief Constructor with a list of passwords.
     * @param passwords List of passwords to use for decryption
     */
    ParallelPThreadDecryptor(std::vector<std::string> passwords);

    /**
     * @brief Constructor with a specified number of threads and a list of passwords.
     * @param numThreads Number of threads to use for decryption
     * @param passwords List of passwords to use for decryption
     */
    ParallelPThreadDecryptor(int numThreads, std::vector<std::string> passwords);

    /**
     * @brief Destructor.
     */
    ~ParallelPThreadDecryptor() override = default;

    /**
     * @brief Decrypts an encrypted password using pthreads.
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

  private:
    /**
     * @brief Thread function for performing decryption.
     *
     * Each thread executes this function to attempt to decrypt the password
     * using a specific range of the provided password list.
     *
     * @param arg A pointer to the ThreadData structure containing thread-specific data
     * @return nullptr
     */
    static void* DecryptThread(void* arg);
};

} // namespace passwordcracker

#endif // PARALLEL_PTHREAD_DECRYPTOR_H
