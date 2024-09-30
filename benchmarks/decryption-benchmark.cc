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

    std::string randomPassword;
    std::string salt = "Parallel";
    std::string encryptedRandomPassword;

    double minTimeSeq = std::numeric_limits<double>::max();
    double maxTimeSeq = std::numeric_limits<double>::min();
    double totalTimeSeq = 0.0;

    double minTimePar = std::numeric_limits<double>::max();
    double maxTimePar = std::numeric_limits<double>::min();
    double totalTimePar = 0.0;

    for (int i = 0; i < numExecutions; ++i)
    {
        randomPassword = passwords[dis(gen)];
        encryptedRandomPassword = crypt(randomPassword.c_str(), salt.c_str());

        auto startTimeSeq = std::chrono::high_resolution_clock::now();
        auto [decryptedSeq, decryptedPasswordSeq] =
            sequentialDecryption->Decrypt(encryptedRandomPassword);
        auto endTimeSeq = std::chrono::high_resolution_clock::now();
        auto timeSeq =
            std::chrono::duration_cast<std::chrono::microseconds>(endTimeSeq - startTimeSeq)
                .count() /
            1000.f;

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

        auto startTimePar = std::chrono::high_resolution_clock::now();
        auto [decryptedPar, decryptedPasswordPar] =
            parallelDecryption->Decrypt(encryptedRandomPassword);
        auto endTimePar = std::chrono::high_resolution_clock::now();
        auto timePar =
            std::chrono::duration_cast<std::chrono::microseconds>(endTimePar - startTimePar)
                .count() /
            1000.f;

        if (decryptedPar)
        {
            if (timePar < minTimePar)
                minTimePar = timePar;
            if (timePar > maxTimePar)
                maxTimePar = timePar;
            totalTimePar += timePar;
        }
        else
        {
            std::cerr << "Error: Parallel Decryption failed" << std::endl;
        }
    }

    double avgTimeSeq = totalTimeSeq / numExecutions;
    double avgTimePar = totalTimePar / numExecutions;

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
