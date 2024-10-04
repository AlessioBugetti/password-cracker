/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

#ifndef PARALLEL_DECRYPTOR_H
#define PARALLEL_DECRYPTOR_H

#include "decryptor.h"

namespace passwordcracker
{

/**
 * @brief Abstract base class for decryptor based on parallel processing.
 */
class ParallelDecryptor : public Decryptor
{
  public:
    /**
     * @brief Default constructor.
     */
    ParallelDecryptor();

    /**
     * @brief Constructor with a specified number of threads.
     * @param numThreads Number of threads to use for decryption
     */
    ParallelDecryptor(int numThreads);

    /**
     * @brief Constructor with a list of passwords.
     * @param passwords List of passwords to use for decryption
     */
    ParallelDecryptor(std::vector<std::string> passwords);

    /**
     * @brief Constructor with a specified number of threads and a list of passwords.
     * @param numThreads Number of threads to use for decryption
     * @param passwords List of passwords to use for decryption
     */
    ParallelDecryptor(int numThreads, std::vector<std::string> passwords);

    /**
     * @brief Virtual destructor.
     */
    virtual ~ParallelDecryptor() override = default;

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

  private:
    int numThreads; ///< Number of threads to use for decryption.
};

} // namespace passwordcracker

#endif // PARALLEL_DECRYPTOR_H
