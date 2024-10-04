/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

#include "sequential-decryptor.h"
#include <gtest/gtest.h>
#include <memory>
#include <unistd.h>

using namespace passwordcracker;

TEST(SequentialDecryptorTest, DecryptSuccess)
{
    std::vector<std::string> passwords = {"acqua", "vento", "aria", "fuoco"};
    auto decryptor = std::make_unique<SequentialDecryptor>(passwords);

    std::string encryptedPassword = crypt("aria", "pc");
    auto [found, decryptedPassword, time] = decryptor->Decrypt(encryptedPassword);

    EXPECT_TRUE(found);
    EXPECT_EQ(decryptedPassword, "aria");
}

TEST(SequentialDecryptorTest, DecryptFailure)
{
    std::vector<std::string> passwords = {"acqua", "vento", "aria", "fuoco"};
    auto decryptor = std::make_unique<SequentialDecryptor>(passwords);

    std::string encryptedPassword = crypt("terra", "pc");
    auto [found, decryptedPassword, time] = decryptor->Decrypt(encryptedPassword);

    EXPECT_FALSE(found);
    EXPECT_EQ(decryptedPassword, "");
}
