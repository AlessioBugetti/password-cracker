/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

#ifndef PARALLEL_OPENMP_DECRYPTION_H
#define PARALLEL_OPENMP_DECRYPTION_H

#include "decryption-strategy.h"

namespace passwordcracker
{

class ParallelOmpDecryption : public DecryptionStrategy
{
  public:
    ParallelOmpDecryption(int numThreads);

    ParallelOmpDecryption(std::vector<std::string> passwords);

    ParallelOmpDecryption(int numThreads, std::vector<std::string> passwords);

    ~ParallelOmpDecryption() = default;

    int GetNumThreads() const;

    void SetNumThreads(int numThreads);

    std::tuple<bool, std::string> Decrypt(const std::string& encryptedPassword) const override;

  private:
    int numThreads;
};

} // namespace passwordcracker

#endif // PARALLEL_OPENMP_DECRYPTION_H