/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

#include "parallel-pthread-decryptor.h"

#ifdef __linux__
#include <crypt.h>
#else
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/des.h>
#endif
#include <pthread.h>

namespace passwordcracker
{

ParallelPThreadDecryptor::ParallelPThreadDecryptor()
    : ParallelDecryptor()
{
}

ParallelPThreadDecryptor::ParallelPThreadDecryptor(int numThreads)
    : ParallelDecryptor(numThreads)
{
}

ParallelPThreadDecryptor::ParallelPThreadDecryptor(std::vector<std::string> passwords)
    : ParallelDecryptor(passwords)
{
}

ParallelPThreadDecryptor::ParallelPThreadDecryptor(int numThreads,
                                                   std::vector<std::string> passwords)
    : ParallelDecryptor(numThreads, passwords)
{
}

void*
ParallelPThreadDecryptor::DecryptWorker(void* arg)
{
    ThreadData* data = static_cast<ThreadData*>(arg);

#ifdef __linux__
    struct crypt_data cryptBuffer;
    cryptBuffer.initialized = 0;
#else
    char cryptBuffer[14] = {0};
#endif

    for (int i = data->start; i < data->end; ++i)
    {
        if (data->index->load() != -1)
            return nullptr; // Early exit if another thread found the password

#ifdef __linux__
        std::string encryptedTmpPassword =
            crypt_r((*data->passwords)[i].c_str(), data->salt->c_str(), &cryptBuffer);
#else
        std::string encryptedTmpPassword =
            DES_fcrypt((*data->passwords)[i].c_str(), data->salt->c_str(), cryptBuffer);
#endif

        if (encryptedTmpPassword == *data->encryptedPassword)
        {
            data->index->store(i);
            return nullptr;
        }
    }

    return nullptr;
}

std::tuple<bool, std::string>
ParallelPThreadDecryptor::Decrypt(const std::string& encryptedPassword) const
{
    const std::vector<std::string>& passwords = GetPasswords();
    int numPasswords = passwords.size();
    std::string salt = encryptedPassword.substr(0, 2);

    std::atomic<int> index(-1);
    int numThreads = GetNumThreads();
    std::vector<pthread_t> threads(numThreads);
    std::vector<ThreadData> threadData(numThreads);

    int chunkSize = (numPasswords + numThreads - 1) / numThreads; // Divide workload

    for (int i = 0; i < numThreads; ++i)
    {
        int start = i * chunkSize;
        int end = std::min(start + chunkSize, numPasswords);

        threadData[i] = {&passwords, &encryptedPassword, &salt, &index, start, end};
        pthread_create(&threads[i], nullptr, DecryptWorker, &threadData[i]);
    }

    for (pthread_t& thread : threads)
    {
        pthread_join(thread, nullptr);
    }

    if (index.load() == -1)
    {
        return {false, ""};
    }
    else
    {
        return {true, passwords[index.load()]};
    }
}

} // namespace passwordcracker
