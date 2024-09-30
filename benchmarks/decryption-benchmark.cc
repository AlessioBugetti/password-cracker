/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

#include "parallel-omp-decryption.h"
#include "sequential-decryption.h"
#include <chrono>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <omp.h>
#include <random>
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

    std::string inputFile = "data/10-million-password-list-top-1000000.txt";
    std::string outputFile = "data/filtered-passwords.txt";
    FilterPasswords(inputFile, outputFile);

    DecryptionStrategy* sequentialDecryption = new SequentialDecryption();
    DecryptionStrategy* parallelDecryption = new ParallelOmpDecryption(numThreads);

    sequentialDecryption->LoadPasswords(outputFile);
    parallelDecryption->LoadPasswords(outputFile);

    std::vector<std::string> passwords = sequentialDecryption->GetPasswords();
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, passwords.size() - 1);
    std::vector<std::string> randomPasswords;
    randomPasswords.reserve(numExecutions);
    for (int i = 0; i < numExecutions; ++i)
    {
        randomPasswords.push_back(passwords[dis(gen)]);
    }

    std::string salt = "pc";
    std::string encryptedRandomPassword;

    double minTimeSeq = std::numeric_limits<double>::max();
    double maxTimeSeq = std::numeric_limits<double>::min();
    double totalTime = 0.0;

    std::chrono::steady_clock::time_point startTime;
    std::chrono::steady_clock::time_point endTime;
    float time;

    for (int i = 0; i < numExecutions; ++i)
    {
        encryptedRandomPassword = crypt(randomPasswords[i].c_str(), salt.c_str());

        startTime = std::chrono::high_resolution_clock::now();
        auto [decryptedSeq, decryptedPasswordSeq] =
            sequentialDecryption->Decrypt(encryptedRandomPassword);
        endTime = std::chrono::high_resolution_clock::now();
        time = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count() /
               1000.f;

        if (decryptedSeq)
        {
            if (time < minTimeSeq)
                minTimeSeq = time;
            if (time > maxTimeSeq)
                maxTimeSeq = time;
            totalTime += time;
        }
        else
        {
            std::cerr << "Error: Sequential Decryption failed" << std::endl;
        }
    }

    double avgTimeSeq = totalTime / numExecutions;

    double minTimePar = std::numeric_limits<double>::max();
    double maxTimePar = std::numeric_limits<double>::min();
    totalTime = 0.0;

    for (int i = 0; i < numExecutions; ++i)
    {
        encryptedRandomPassword = crypt(randomPasswords[i].c_str(), salt.c_str());

        startTime = std::chrono::high_resolution_clock::now();
        auto [decryptedPar, decryptedPasswordPar] =
            parallelDecryption->Decrypt(encryptedRandomPassword);
        endTime = std::chrono::high_resolution_clock::now();
        time = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count() /
               1000.f;
        std::cout << "Decrypted password: " << decryptedPasswordPar << " Time: " << time
                  << std::endl;

        if (decryptedPar)
        {
            if (time < minTimePar)
                minTimePar = time;
            if (time > maxTimePar)
                maxTimePar = time;
            totalTime += time;
        }
        else
        {
            std::cerr << "Error: Sequential Decryption failed" << std::endl;
        }
    }

    double avgTimePar = totalTime / numExecutions;

    std::cout << "Sequential Decryption:" << std::endl;
    std::cout << "Min time: " << minTimeSeq << " ms" << std::endl;
    std::cout << "Max time: " << maxTimeSeq << " ms" << std::endl;
    std::cout << "Average time: " << avgTimeSeq << " ms" << std::endl;

    std::cout << std::endl;

    std::cout << "Parallel Decryption:" << std::endl;
    std::cout << "Min time: " << minTimePar << " ms" << std::endl;
    std::cout << "Max time: " << maxTimePar << " ms" << std::endl;
    std::cout << "Average time: " << avgTimePar << " ms" << std::endl;

    return 0;
}
