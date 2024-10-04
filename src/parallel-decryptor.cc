/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

#include "parallel-decryptor.h"

#include <thread>

namespace passwordcracker
{

ParallelDecryptor::ParallelDecryptor()
    : numThreads(std::thread::hardware_concurrency() > 0 ? std::thread::hardware_concurrency() : 1)
{
}

ParallelDecryptor::ParallelDecryptor(int numThreads)
    : numThreads(numThreads)
{
}

ParallelDecryptor::ParallelDecryptor(std::vector<std::string> passwords)
    : Decryptor(passwords),
      numThreads(std::thread::hardware_concurrency() > 0 ? std::thread::hardware_concurrency() : 1)
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
