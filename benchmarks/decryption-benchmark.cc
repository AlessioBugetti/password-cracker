/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

#include "parallel-omp-decryption.h"
#include "sequential-decryption.h"

#include <chrono>
#include <crypt.h>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <omp.h>
#include <random>
#include <regex>
#include <unistd.h>

using namespace passwordcracker;

void
DecompressTarGz(const std::string& inputFile, const std::string& outputFile)
{
    std::string command = "tar -xzf " + inputFile + " -C " + outputFile;
    int result = system(command.c_str());
    if (result != 0)
    {
        throw std::runtime_error("Failed to extract " + inputFile);
    }
}

void
FilterPasswords(const std::string& filePath)
{
    std::ifstream infile(filePath);
    std::string password;
    std::regex filterRegex(R"(^[a-zA-Z0-9./]{8}$)");

    std::vector<std::string> validPasswords;

    if (!infile.is_open())
    {
        std::cerr << "Error opening file" << std::endl;
        return;
    }

    while (std::getline(infile, password))
    {
        if (std::regex_match(password, filterRegex))
        {
            validPasswords.push_back(password);
        }
    }
    infile.close();

    std::ofstream outfile(filePath, std::ios::trunc);
    if (!outfile.is_open())
    {
        std::cerr << "Error opening file for writing" << std::endl;
        return;
    }

    for (const auto& validPassword : validPasswords)
    {
        outfile << validPassword << std::endl;
    }
    outfile.close();
}

int
main(int argc, char** argv)
{
    int numExecutions = 2;
    bool numExecutionsSpecified = false;
    int numThreads = 4;
    bool numThreadsSpecified = false;

    struct option longOptions[] = {{"numExecutions", required_argument, 0, 'e'},
                                   {"numThreads", required_argument, 0, 't'},
                                   {0, 0}};

    int optionIndex = 0;
    int c;
    while ((c = getopt_long(argc, argv, "spe:t:", longOptions, &optionIndex)) != -1)
    {
        switch (c)
        {
        case 'e':
            numExecutions = std::stoi(optarg);
            numExecutionsSpecified = true;
            break;
        case 't':
            numThreads = std::stoi(optarg);
            numThreadsSpecified = true;
            break;
        default:
            std::cerr << "Usage: " << argv[0] << " [--numExecutions=<num>] [--numThreads=<num>]"
                      << std::endl;
            return 1;
        }
    }

    if (!numExecutionsSpecified)
    {
        std::cerr << "Error: You must specify --numExecutions for the number of executions."
                  << std::endl;
        return 1;
    }

    if (!numThreadsSpecified)
    {
        std::cerr << "Error: You must specify --numThreads for parallel mode." << std::endl;
        return 1;
    }

    std::string inputFile = "data/rockyou.txt.tar.gz";
    std::string outputDir = "data/";
    std::string extractedFile = "data/rockyou.txt";

    try
    {
        DecompressTarGz(inputFile, outputDir);
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    FilterPasswords(extractedFile);

    DecryptionStrategy* sequentialDecryption = new SequentialDecryption();
    DecryptionStrategy* parallelDecryption = new ParallelOmpDecryption(numThreads);

    sequentialDecryption->LoadPasswords(extractedFile);
    parallelDecryption->LoadPasswords(extractedFile);

    if (sequentialDecryption->GetPasswords().size() != parallelDecryption->GetPasswords().size())
    {
        std::cerr << "Error: Passwords loaded by sequential and parallel decryption are different"
                  << std::endl;
        return 1;
    }

    std::vector<std::string> passwords = sequentialDecryption->GetPasswords();
    int seed = 42;
    std::mt19937 gen(seed);
    std::uniform_int_distribution<> dis(0, passwords.size() - 1);
    std::vector<std::string> randomPasswords;
    for (int i = 0; i < numExecutions; ++i)
    {
        randomPasswords.push_back(passwords[dis(gen)]);
    }

    std::string salt = "pc";
    std::string encryptedRandomPassword;

    double minTimeSeq = std::numeric_limits<double>::max();
    double maxTimeSeq = std::numeric_limits<double>::min();
    double totalTimeSeq = 0.0;

    double minTimePar = std::numeric_limits<double>::max();
    double maxTimePar = std::numeric_limits<double>::min();
    double totalTimePar = 0.0;

    std::vector<double> speedups;

    for (int i = 0; i < numExecutions; ++i)
    {
        encryptedRandomPassword = crypt(randomPasswords[i].c_str(), salt.c_str());

        auto [decryptedSeq, decryptedPasswordSeq, timeSeq] =
            sequentialDecryption->Decrypt(encryptedRandomPassword);

        if (decryptedSeq)
        {
            if (timeSeq < minTimeSeq)
                minTimeSeq = timeSeq;
            if (timeSeq > maxTimeSeq)
                maxTimeSeq = timeSeq;
            totalTimeSeq += timeSeq;
        }
        else
        {
            std::cerr << "Error: Sequential Decryption failed" << std::endl;
        }

        auto [decryptedPar, decryptedPasswordPar, timePar] =
            parallelDecryption->Decrypt(encryptedRandomPassword);

        if (decryptedPar)
        {
            if (timePar < minTimePar)
                minTimePar = timePar;
            if (timePar > maxTimePar)
                maxTimePar = timePar;
            totalTimePar += timePar;

            if (timePar > 0.0)
            {
                speedups.push_back(timeSeq / timePar);
            }
        }
        else
        {
            std::cerr << "Error: Parallel Decryption failed" << std::endl;
        }
    }

    double avgTimeSeq = totalTimeSeq / numExecutions;
    double avgTimePar = totalTimePar / numExecutions;

    double minSpeedup = std::numeric_limits<double>::max();
    double maxSpeedup = std::numeric_limits<double>::min();
    double totalSpeedup = 0.0;

    for (double sp : speedups)
    {
        if (sp < minSpeedup)
            minSpeedup = sp;
        if (sp > maxSpeedup)
            maxSpeedup = sp;
        totalSpeedup += sp;
    }

    double avgSpeedup = speedups.empty() ? 0.0 : (totalSpeedup / speedups.size());

    std::cout << "Sequential Decryption:" << std::endl;
    std::cout << "Min time: " << minTimeSeq << " ms" << std::endl;
    std::cout << "Max time: " << maxTimeSeq << " ms" << std::endl;
    std::cout << "Average time: " << avgTimeSeq << " ms" << std::endl;

    std::cout << std::endl;

    std::cout << "Parallel Decryption:" << std::endl;
    std::cout << "Min time: " << minTimePar << " ms" << std::endl;
    std::cout << "Max time: " << maxTimePar << " ms" << std::endl;
    std::cout << "Average time: " << avgTimePar << " ms" << std::endl;

    std::cout << std::endl;

    std::cout << "Speedup:" << std::endl;
    std::cout << "Min speedup: " << minSpeedup << "x" << std::endl;
    std::cout << "Max speedup: " << maxSpeedup << "x" << std::endl;
    std::cout << "Average speedup: " << avgSpeedup << "x" << std::endl;

    return 0;
}
