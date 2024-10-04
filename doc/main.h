/**
 * @mainpage Password Cracker Documentation
 *
 * @section intro Introduction
 * The **Password Cracker** project implements both sequential and parallel brute-force decryption
 * of DES-encrypted passwords. It focuses on 8-character passwords from the set [a-zA-Z0-9./].
 *
 * @section class Class overview
 * The following classes are implemented:
 * - @ref passwordcracker::Decryptor "Decryptor"
 * - @ref passwordcracker::ParallelDecryptor "ParallelDecryptor"
 * - @ref passwordcracker::SequentialDecryptor "SequentialDecryptor"
 * - @ref passwordcracker::ParallelOmpDecryptor "ParallelOmpDecryptor"
 * - @ref passwordcracker::ParallelPThreadDecryptor "ParallelPThreadDecryptor"
 *
 * @section inheritance Class Inheritance
 * The class inheritance structure is as follows:
 *
 * ```
 * Decryptor (abstract)
 *     ├── SequentialDecryptor
 *     └── ParallelDecryptor (abstract)
 *             ├── ParallelOmpDecryptor
 *             └── ParallelPThreadDecryptor
 * ```
 *
 * - `Decryptor` is an abstract base class.
 * - `ParallelDecryptor` is an abstract class that inherits from `Decryptor`.
 * - `SequentialDecryptor` inherits from `Decryptor` and is a concrete class.
 * - `ParallelOmpDecryptor` inherits from `ParallelDecryptor` and implements parallel decryption
 * using OpenMP.
 * - `ParallelPThreadDecryptor` inherits from `ParallelDecryptor` and implements parallel decryption
 * using PThreads.
 */
