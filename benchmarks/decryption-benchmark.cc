/*
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Author: Alessio Bugetti <alessiobugetti98@gmail.com>
 */

#include "parallel-omp-decryptor.h"
#include "parallel-pthread-decryptor.h"
#include "sequential-decryptor.h"

#include <fstream>
#include <getopt.h>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <omp.h>
#include <optional>
#include <regex>
#include <unistd.h>

#define SALT "pc"

using namespace passwordcracker;

bool
FileExists(const std::string& filename)
{
    std::ifstream file(filename);
    return file.good();
}

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

    if (!infile.is_open())
    {
        std::cerr << "Error opening file" << std::endl;
        return;
    }

    std::string password;
    std::regex filterRegex(R"(^[a-zA-Z0-9./]{8}$)");
    std::vector<std::string> validPasswords;

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
    int numThreads[] = {4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64};
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
    if (!FileExists(extractedFile))
    {
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
    }

    auto sequentialDecryptor = std::make_unique<SequentialDecryptor>();
    auto parallelPThreadDecryptor = std::make_unique<ParallelPThreadDecryptor>();
    auto parallelOmpDecryptor = std::make_unique<ParallelOmpDecryptor>();

    sequentialDecryptor->LoadPasswords(extractedFile);
    parallelPThreadDecryptor->LoadPasswords(extractedFile);
    parallelOmpDecryptor->LoadPasswords(extractedFile);

    if (sequentialDecryptor->GetPasswords().size() != parallelOmpDecryptor->GetPasswords().size())
    {
        std::cerr
            << "Error: Passwords loaded by sequential and parallel omp decryption are different"
            << std::endl;
        return 1;
    }

    if (sequentialDecryptor->GetPasswords().size() !=
        parallelPThreadDecryptor->GetPasswords().size())
    {
        std::cerr << "Error: Passwords loaded by sequential and parallel pthreads decryption are "
                     "different"
                  << std::endl;
        return 1;
    }

    if (parallelOmpDecryptor->GetPasswords().size() !=
        parallelPThreadDecryptor->GetPasswords().size())
    {
        std::cerr << "Error: Passwords loaded by parallel omp and parallel pthreads decryption are "
                     "different"
                  << std::endl;
        return 1;
    }

    std::vector<std::string> allPasswords = sequentialDecryptor->GetPasswords();
    std::vector<std::string> passwords;
    passwords.reserve(3);

    if (allPasswords.size() > 1024)
    {
        passwords.push_back(allPasswords[1024]);
    }
    if (allPasswords.size() > 1414582)
    {
        passwords.push_back(allPasswords[1414582]);
    }
    if (allPasswords.size() > 2829163)
    {
        passwords.push_back(allPasswords[2829163]);
    }

    std::vector<std::string> encryptedPasswords;
    encryptedPasswords.reserve(passwords.size());

    for (int i = 0; i < passwords.size(); i++)
    {
        encryptedPasswords.push_back(crypt(passwords[i].c_str(), SALT));
    }

    double startTimeSeq;
    double endTimeSeq;
    double timeSeq;
    double minTimeSeq = std::numeric_limits<double>::max();
    double maxTimeSeq = std::numeric_limits<double>::min();
    double totalTimeSeq = 0.0;
    double avgTimeSeq;

    struct ParallelStats
    {
        double minTimePar = std::numeric_limits<double>::max();
        double maxTimePar = std::numeric_limits<double>::min();
        double totalTimePar = 0.0;
    };

    double startTimePThreadPar;
    double endTimePThreadPar;
    double timePThreadPar;
    std::map<int, ParallelStats> parallelPThreadStatsMap;
    double avgTimePThreadPar;
    double pthreadSpeedup;

    double startTimeOmpPar;
    double endTimeOmpPar;
    double timeOmpPar;
    std::map<int, ParallelStats> parallelOmpStatsMap;
    double avgTimeOmpPar;
    double ompSpeedup;

    for (int i = 0; i < encryptedPasswords.size(); i++)
    {
        std::cout << "Benchmarking decryption for password: " << passwords[i] << std::endl
                  << std::endl;
        for (int j = 0; j < numExecutions; j++)
        {
            startTimeSeq = omp_get_wtime();
            auto [foundSeq, decryptedPasswordSeq] =
                sequentialDecryptor->Decrypt(encryptedPasswords[i]);
            endTimeSeq = omp_get_wtime();
            timeSeq = (endTimeSeq - startTimeSeq) * 1000;
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
                std::cerr << "Error: Sequential Decryption failed for execution " << j + 1
                          << std::endl;
            }
        }

        for (const int& numThread : numThreads)
        {
            parallelPThreadDecryptor->SetNumThreads(numThread);
            parallelOmpDecryptor->SetNumThreads(numThread);

            for (int j = 0; j < numExecutions; j++)
            {
                startTimePThreadPar = omp_get_wtime();
                auto [foundPThreadPar, decryptedPasswordPThreadPar] =
                    parallelPThreadDecryptor->Decrypt(encryptedPasswords[i]);
                endTimePThreadPar = omp_get_wtime();
                timePThreadPar = (endTimePThreadPar - startTimePThreadPar) * 1000;

                if (foundPThreadPar)
                {
                    ParallelStats& parPThreadStats = parallelPThreadStatsMap[numThread];
                    if (timePThreadPar < parPThreadStats.minTimePar)
                        parPThreadStats.minTimePar = timePThreadPar;
                    if (timePThreadPar > parPThreadStats.maxTimePar)
                        parPThreadStats.maxTimePar = timePThreadPar;
                    parPThreadStats.totalTimePar += timePThreadPar;
                }
                else
                {
                    std::cerr << "Error: Parallel PThreads Decryption failed for execution "
                              << j + 1 << " with " << numThread << " threads" << std::endl;
                }

                startTimeOmpPar = omp_get_wtime();
                auto [foundOmpPar, decryptedPasswordOmpPar] =
                    parallelOmpDecryptor->Decrypt(encryptedPasswords[i]);
                endTimeOmpPar = omp_get_wtime();
                timeOmpPar = (endTimeOmpPar - startTimeOmpPar) * 1000;

                if (foundOmpPar)
                {
                    ParallelStats& parOmpStats = parallelOmpStatsMap[numThread];
                    if (timeOmpPar < parOmpStats.minTimePar)
                        parOmpStats.minTimePar = timeOmpPar;
                    if (timeOmpPar > parOmpStats.maxTimePar)
                        parOmpStats.maxTimePar = timeOmpPar;
                    parOmpStats.totalTimePar += timeOmpPar;
                }
                else
                {
                    std::cerr << "Error: Parallel Omp Decryption failed for execution " << j + 1
                              << " with " << numThread << " threads" << std::endl;
                }
            }
        }

        avgTimeSeq = totalTimeSeq / numExecutions.value();

        std::cout << "Sequential Decryption:" << std::endl;

        std::cout << std::left << std::setw(20) << "Min Time (ms)" << std::setw(20)
                  << "Max Time (ms)" << std::setw(20) << "Avg Time (ms)" << std::endl;

        std::cout << std::left << std::setw(20) << minTimeSeq << std::setw(20) << maxTimeSeq
                  << std::setw(20) << avgTimeSeq << std::endl;

        std::cout << "\nParallel Omp Decryption and Speedup:" << std::endl;

        std::cout << std::left << std::setw(12) << "Threads" << std::right << std::setw(20)
                  << "Min Time (ms)" << std::setw(20) << "Max Time (ms)" << std::setw(20)
                  << "Avg Time (ms)" << std::setw(20) << "Speedup" << std::endl;

        for (const int& numThread : numThreads)
        {
            const ParallelStats& parOmpStats = parallelOmpStatsMap[numThread];

            avgTimeOmpPar = parOmpStats.totalTimePar / numExecutions.value();
            ompSpeedup = avgTimeSeq / avgTimeOmpPar;

            std::cout << std::left << std::setw(12) << numThread << std::right << std::setw(20)
                      << parOmpStats.minTimePar << std::setw(20) << parOmpStats.maxTimePar
                      << std::setw(20) << avgTimeOmpPar << std::setw(20) << ompSpeedup << std::endl;
        }

        std::cout << "\nParallel PThreads Decryption and Speedup:" << std::endl;

        std::cout << std::left << std::setw(12) << "Threads" << std::right << std::setw(20)
                  << "Min Time (ms)" << std::setw(20) << "Max Time (ms)" << std::setw(20)
                  << "Avg Time (ms)" << std::setw(20) << "Speedup" << std::endl;

        for (const int& numThread : numThreads)
        {
            const ParallelStats& parPThreadStats = parallelPThreadStatsMap[numThread];

            avgTimePThreadPar = parPThreadStats.totalTimePar / numExecutions.value();
            pthreadSpeedup = avgTimeSeq / avgTimePThreadPar;

            std::cout << std::left << std::setw(12) << numThread << std::right << std::setw(20)
                      << parPThreadStats.minTimePar << std::setw(20) << parPThreadStats.maxTimePar
                      << std::setw(20) << avgTimePThreadPar << std::setw(20) << pthreadSpeedup
                      << std::endl;
        }
        std::cout << std::endl;
        parallelPThreadStatsMap.clear();
        parallelOmpStatsMap.clear();
        minTimeSeq = std::numeric_limits<double>::max();
        maxTimeSeq = std::numeric_limits<double>::min();
        totalTimeSeq = 0.0;
    }

    return 0;
}
