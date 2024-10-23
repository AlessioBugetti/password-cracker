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
#include <atomic>
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

struct ThreadData
{
    const std::vector<std::string>* passwords;
    const std::string* encryptedPassword;
    int startIndex;
    int endIndex;
    std::atomic<int>* index;
};

void*
ParallelPThreadDecryptor::DecryptThread(void* arg)
{
    ThreadData* threadData = static_cast<ThreadData*>(arg);
    std::string salt = threadData->encryptedPassword->substr(0, 2);

#ifdef __linux__
    struct crypt_data data;
    data.initialized = 0;
#else
    char data[14] = {0};
#endif

    if (threadData->index->load() != -1)
    {
        return nullptr;
    }

    for (int i = threadData->startIndex;
         i < threadData->endIndex && threadData->index->load() == -1;
         i++)
    {
#ifdef __linux__
        std::string encryptedTmpPassword =
            crypt_r((*threadData->passwords)[i].c_str(), salt.c_str(), &data);
#else
        DES_fcrypt((*threadData->passwords)[i].c_str(), salt.c_str(), data);
        std::string encryptedTmpPassword(data);
#endif

        if (encryptedTmpPassword == *(threadData->encryptedPassword))
        {
            threadData->index->store(i);
            return nullptr;
        }
    }
    return nullptr;
}

std::tuple<bool, std::string>
ParallelPThreadDecryptor::Decrypt(const std::string& encryptedPassword) const
{
    std::atomic<int> index(-1);

    int numThreads = GetNumThreads();

    std::vector<pthread_t> threads(numThreads);
    std::vector<ThreadData> threadData(numThreads);

    const std::vector<std::string>& passwords = GetPasswords();
    int chunkSize = passwords.size() / numThreads;
    int remaining = passwords.size() % numThreads;

    for (int i = 0; i < numThreads; i++)
    {
        int startIndex = i * chunkSize;
        int endIndex =
            (i == numThreads - 1) ? (startIndex + chunkSize + remaining) : (startIndex + chunkSize);

        threadData[i] = {&passwords, &encryptedPassword, startIndex, endIndex, &index};
        pthread_create(&threads[i], nullptr, DecryptThread, (void*)&threadData[i]);
    }

    for (auto& thread : threads)
    {
        pthread_join(thread, nullptr);
    }

    if (index.load() != -1)
    {
        return {true, passwords[index.load()]};
    }
    else
    {
        return {false, ""};
    }
}

} // namespace passwordcracker
