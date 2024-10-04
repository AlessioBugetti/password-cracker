/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

#ifndef PARALLEL_OPENMP_DECRYPTOR_H
#define PARALLEL_OPENMP_DECRYPTOR_H

#include "decryptor.h"

namespace passwordcracker
{

/**
 * @brief Decryptor strategy using OpenMP for parallel processing.
 */
class ParallelOmpDecryptor : public Decryptor
{
  public:
    /**
     * @brief Default constructor.
     *
     * Sets the number of threads to the value returned by the ‘omp_get_max_threads()’ function from
     * the `<omp.h>` header.
     */
    ParallelOmpDecryptor();

    /**
     * @brief Constructor with a specified number of threads.
     * @param numThreads Number of threads to use for decryption
     */
    ParallelOmpDecryptor(int numThreads);

    /**
     * @brief Constructor with a list of passwords.
     * @param passwords List of passwords to use for decryption
     */
    ParallelOmpDecryptor(std::vector<std::string> passwords);

    /**
     * @brief Constructor with a specified number of threads and a list of passwords.
     * @param numThreads Number of threads to use for decryption
     * @param passwords List of passwords to use for decryption
     */
    ParallelOmpDecryptor(int numThreads, std::vector<std::string> passwords);

    /**
     * @brief Destructor.
     */
    ~ParallelOmpDecryptor() override = default;

    /**
     * @brief Gets the number of threads.
     * @return Number of threads
     */
    int GetNumThreads() const;

    /**
     * @brief Sets the number of threads.
     * @param numThreads Number of threads to use for decryption
     */
    void SetNumThreads(int numThreads);

    /**
     * @brief Decrypts an encrypted password using parallel processing.
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
    int numThreads; ///< Number of threads to use for decryption.
};

} // namespace passwordcracker

#endif // PARALLEL_OPENMP_DECRYPTOR_H
