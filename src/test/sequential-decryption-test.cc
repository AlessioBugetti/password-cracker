#include "sequential-decryption.h"
#include <gtest/gtest.h>

namespace passwordcracker
{

TEST(SequentialDecryptionTest, DecryptSuccess)
{
    std::vector<std::string> passwords = {"acqua", "vento", "aria", "fuoco"};
    DecryptionStrategy* decryptor = new SequentialDecryption(passwords);

    std::string encryptedPassword = crypt("aria", "pc");
    auto [found, decryptedPassword] = decryptor->Decrypt(encryptedPassword);

    EXPECT_TRUE(found);
    EXPECT_EQ(decryptedPassword, "aria");
}

TEST(SequentialDecryptionTest, DecryptFailure)
{
    std::vector<std::string> passwords = {"acqua", "vento", "aria", "fuoco"};
    DecryptionStrategy* decryptor = new SequentialDecryption(passwords);

    std::string encryptedPassword = crypt("terra", "pc");
    auto [found, decryptedPassword] = decryptor->Decrypt(encryptedPassword);

    EXPECT_FALSE(found);
    EXPECT_EQ(decryptedPassword, "");
}

} // namespace passwordcracker
