/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

#include "sequential-decryption.h"
#include <fstream>
#include <iostream>
#include <regex>
#include <unistd.h>

using namespace passwordcracker;

void
FilterPasswords(const std::string& input_file, const std::string& output_file)
{
    std::ifstream infile(input_file);
    std::ofstream outfile(output_file);
    std::string password;
    std::regex filterRegex(R"(^[a-zA-Z0-9./]{8}$)");

    if (!infile.is_open() || !outfile.is_open())
    {
        std::cerr << "Error opening file" << std::endl;
        return;
    }

    while (std::getline(infile, password))
    {
        if (std::regex_match(password, filterRegex))
        {
            outfile << password << std::endl;
        }
    }

    infile.close();
    outfile.close();
}

int
main(int argc, char** argv)
{
    std::string inputFile = "data/10-million-password-list-top-1000000.txt";
    std::string outputFile = "data/filtered-passwords.txt";
    FilterPasswords(inputFile, outputFile);

    std::string password = "Maverick";
    std::string salt = "parallel";

    DecryptionStrategy* decryptionStrategy = new SequentialDecryption();
    decryptionStrategy->LoadPasswords(outputFile);
    std::string encryptedPassword = crypt(password.c_str(), salt.c_str());

    auto [decrypted, decryptedPassword] = decryptionStrategy->Decrypt(encryptedPassword);
    if (decrypted)
    {
        std::cout << "Decrypted password: " << decryptedPassword << std::endl;
    }
    return 0;
}
