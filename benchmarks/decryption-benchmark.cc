/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

#include "parallel-omp-decryption.h"
#include "sequential-decryption.h"
#include <fstream>
#include <getopt.h>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
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
    std::optional<int> numExecutions;

    struct option longOptions[] = {{"numExecutions", required_argument, nullptr, 'e'},
                                   {"help", no_argument, nullptr, 'h'},
                                   {nullptr, 0, nullptr, 0}};

    int optionIndex = 0;
    int c;

    while ((c = getopt_long(argc, argv, "he:", longOptions, &optionIndex)) != -1)
    {
        switch (c)
        {
        case 'e':
            try
            {
                numExecutions = std::stoi(optarg);
                if (numExecutions.value() <= 0)
                {
                    throw std::invalid_argument("must be a positive integer");
                }
            }
            catch (const std::exception& ex)
            {
                std::cerr << "Error: Invalid value for --numExecutions: " << optarg << " ("
                          << ex.what() << "). Must be a positive integer" << std::endl;
                return 1;
            }
            break;
        case 'h':
            std::cout << "Usage: " << argv[0] << " [--numExecutions=<num>] [--help]" << std::endl;
            std::cout << "Options:" << std::endl;
            std::cout << "  -e, --numExecutions=<num>  Specify the number of executions (must be a "
                         "positive integer)"
                      << std::endl;
            std::cout << "  -h, --help                 Show this help message" << std::endl;
            return 0;
        default:
            std::cerr << "Usage: " << argv[0] << " [--numExecutions=<num>] [--help]" << std::endl;
            return 1;
        }
    }

    if (!numExecutions.has_value())
    {
        std::cerr << "Error: You must specify --numExecutions for the number of executions"
                  << std::endl;
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

    auto sequentialDecryption = std::make_unique<SequentialDecryption>();
    auto parallelDecryption = std::make_unique<ParallelOmpDecryption>();

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
    randomPasswords.reserve(numExecutions.value());
    for (int i = 0; i < numExecutions; ++i)
    {
        randomPasswords.push_back(passwords[dis(gen)]);
    }

    std::string salt = "pc";

    std::vector<std::string> encryptedRandomPasswords;
    encryptedRandomPasswords.reserve(numExecutions.value());

    for (int i = 0; i < numExecutions; ++i)
    {
        encryptedRandomPasswords.push_back(crypt(randomPasswords[i].c_str(), salt.c_str()));
    }

    int numThreads[] = {0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64};

    struct ParallelStats
    {
        double minTimePar = std::numeric_limits<double>::max();
        double maxTimePar = std::numeric_limits<double>::min();
        double totalTimePar = 0.0;
    };

    std::map<int, ParallelStats> parallelStatsMap;

    double minTimeSeq = std::numeric_limits<double>::max();
    double maxTimeSeq = std::numeric_limits<double>::min();
    double totalTimeSeq = 0.0;

    for (int i = 0; i < numExecutions; ++i)
    {
        auto [foundSeq, decryptedPasswordSeq, timeSeq] =
            sequentialDecryption->Decrypt(encryptedRandomPasswords[i]);
        if (foundSeq)
        {
            if (timeSeq < minTimeSeq)
                minTimeSeq = timeSeq;
            if (timeSeq > maxTimeSeq)
                maxTimeSeq = timeSeq;
            totalTimeSeq += timeSeq;
        }
        else
        {
            std::cerr << "Error: Sequential Decryption failed for execution " << i + 1 << std::endl;
        }

        for (const int& numThread : numThreads)
        {
            parallelDecryption->SetNumThreads(numThread);
            auto [foundPar, decryptedPasswordPar, timePar] =
                parallelDecryption->Decrypt(encryptedRandomPasswords[i]);
            if (foundPar)
            {
                ParallelStats& parStats = parallelStatsMap[numThread];
                if (timePar < parStats.minTimePar)
                    parStats.minTimePar = timePar;
                if (timePar > parStats.maxTimePar)
                    parStats.maxTimePar = timePar;
                parStats.totalTimePar += timePar;
            }
            else
            {
                std::cerr << "Error: Parallel Decryption failed for execution " << i + 1 << " with "
                          << numThread << " threads" << std::endl;
            }
        }
    }

    double avgTimeSeq = totalTimeSeq / numExecutions.value();

    std::cout << "Sequential Decryption:" << std::endl;

    std::cout << std::left << std::setw(20) << "Min Time (ms)" << std::setw(20) << "Max Time (ms)"
              << std::setw(20) << "Avg Time (ms)" << std::endl;

    std::cout << std::left << std::setw(20) << minTimeSeq << std::setw(20) << maxTimeSeq
              << std::setw(20) << avgTimeSeq << std::endl;

    std::cout << "\nParallel Decryption and Speedup:" << std::endl;

    std::cout << std::left << std::setw(12) << "Threads" << std::right << std::setw(20)
              << "Min Time (ms)" << std::setw(20) << "Max Time (ms)" << std::setw(20)
              << "Avg Time (ms)" << std::setw(20) << "Speedup" << std::endl;

    for (const int& numThread : numThreads)
    {
        const ParallelStats& parStats = parallelStatsMap[numThread];

        double avgTimePar = parStats.totalTimePar / numExecutions.value();
        double speedup = totalTimeSeq / parStats.totalTimePar;

        std::cout << std::left << std::setw(12) << numThread << std::right << std::setw(20)
                  << parStats.minTimePar << std::setw(20) << parStats.maxTimePar << std::setw(20)
                  << avgTimePar << std::setw(20) << speedup << std::endl;
    }

    return 0;
}
