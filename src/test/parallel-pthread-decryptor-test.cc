/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

#include "parallel-pthread-decryptor.h"
#include <gtest/gtest.h>
#include <memory>
#include <unistd.h>

using namespace passwordcracker;

TEST(ParallelPthreadDecryptorTest, DecryptSuccess)
{
    std::vector<std::string> passwords = {"acqua", "vento", "aria", "fuoco"};
    std::string password = "vento";
    std::string salt = "pc";
    auto decryptor = std::make_unique<ParallelPThreadDecryptor>(passwords);

    std::string encryptedPassword = crypt(password.c_str(), salt.c_str());
    auto [found, decryptedPassword, time] = decryptor->Decrypt(encryptedPassword);

    EXPECT_TRUE(found);
    EXPECT_EQ(decryptedPassword, password);
}

TEST(ParallelPthreadDecryptorTest, DecryptFailure)
{
    std::vector<std::string> passwords = {"acqua", "vento", "aria", "fuoco"};
    std::string password = "terra";
    std::string salt = "pc";
    auto decryptor = std::make_unique<ParallelPThreadDecryptor>(passwords);

    std::string encryptedPassword = crypt(password.c_str(), salt.c_str());
    auto [found, decryptedPassword, time] = decryptor->Decrypt(encryptedPassword);

    EXPECT_FALSE(found);
    EXPECT_EQ(decryptedPassword, "");
}
