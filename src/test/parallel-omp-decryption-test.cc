/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

#include "parallel-omp-decryption.h"

#include <gtest/gtest.h>

namespace passwordcracker
{

TEST(ParallelOmpDecryptionTest, DecryptSuccess)
{
    int numThreads = 8;
    std::vector<std::string> passwords = {"acqua", "vento", "aria", "fuoco"};
    DecryptionStrategy* decryptor = new ParallelOmpDecryption(numThreads, passwords);

    std::string encryptedPassword = crypt("aria", "pc");
    auto [found, decryptedPassword, time] = decryptor->Decrypt(encryptedPassword);

    EXPECT_TRUE(found);
    EXPECT_EQ(decryptedPassword, "aria");
}

TEST(ParallelOmpDecryptionTest, DecryptFailure)
{
    int numThreads = 8;
    std::vector<std::string> passwords = {"acqua", "vento", "aria", "fuoco"};
    DecryptionStrategy* decryptor = new ParallelOmpDecryption(numThreads, passwords);

    std::string encryptedPassword = crypt("terra", "pc");
    auto [found, decryptedPassword, time] = decryptor->Decrypt(encryptedPassword);

    EXPECT_FALSE(found);
    EXPECT_EQ(decryptedPassword, "");
}

} // namespace passwordcracker
