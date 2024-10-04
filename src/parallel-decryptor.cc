/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

#include "parallel-decryptor.h"

namespace passwordcracker
{

ParallelDecryptor::ParallelDecryptor(int numThreads)
    : numThreads(numThreads)
{
}

ParallelDecryptor::ParallelDecryptor(int numThreads, std::vector<std::string> passwords)
    : Decryptor(passwords),
      numThreads(numThreads)
{
}

int
ParallelDecryptor::GetNumThreads() const
{
    return numThreads;
}

void
ParallelDecryptor::SetNumThreads(int numThreads)
{
    this->numThreads = numThreads;
}

} // namespace passwordcracker
