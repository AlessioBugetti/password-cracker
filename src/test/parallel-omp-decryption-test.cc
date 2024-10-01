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
    std::string password = "vento";
    std::string salt = "pc";
    DecryptionStrategy* decryptor = new ParallelOmpDecryption(numThreads, passwords);

    std::string encryptedPassword = crypt(password.c_str(), salt.c_str());
    auto [found, decryptedPassword, time] = decryptor->Decrypt(encryptedPassword);

    EXPECT_TRUE(found);
    EXPECT_EQ(decryptedPassword, password);
}

TEST(ParallelOmpDecryptionTest, DecryptFailure)
{
    int numThreads = 8;
    std::vector<std::string> passwords = {"acqua", "vento", "aria", "fuoco"};
    std::string password = "terra";
    std::string salt = "pc";
    DecryptionStrategy* decryptor = new ParallelOmpDecryption(numThreads, passwords);

    std::string encryptedPassword = crypt(password.c_str(), salt.c_str());
    auto [found, decryptedPassword, time] = decryptor->Decrypt(encryptedPassword);

    EXPECT_FALSE(found);
    EXPECT_EQ(decryptedPassword, "");
}

} // namespace passwordcracker
