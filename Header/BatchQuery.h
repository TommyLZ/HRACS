#pragma once

#include "PublicParam.h"
#include "HVC.h"
#include <filesystem>
#include <vector>
#include <iostream>
#include <string>

namespace fs = std::filesystem;

/**
 * @brief Batch Query Phase
 * 
 * This function performs the batch query process, including:
 * 1. Loading the DEK key and deriving the AES key.
 * 2. Loading commitment and randomness values.
 * 3. Reading tag files and hashing them into field elements.
 * 4. Loading and aggregating proof elements for queried indices.
 * 5. Verifying the aggregated proof using the HVC verification function.
 * 6. Decrypting the corresponding ciphertext files.
 * 7. Cleaning up memory and resources.
 */
void BatchQuery()
{
    std::cout << "***************************Batch Query Phase***************************" << std::endl;

    // ------------------- Step 1: Load DEK key -------------------
    std::string seed;
    if (!load_string_from_file("../Storage/seed.txt", seed)) {
        std::cerr << "Failed to load seed.txt\n";
        return;
    }

    // Derive DEK seed and map to Zr
    std::string seed_dek = seed + "DEK";
    element_t k_dek;
    element_init_Zr(k_dek, pairing);
    element_from_hash(k_dek, (void*)seed_dek.c_str(), seed_dek.length());

    // Derive AES-256 key from k_dek
    int len = element_length_in_bytes(k_dek);
    std::vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), k_dek);

    std::vector<unsigned char> key(32);
    SHA256(buf.data(), buf.size(), key.data());

    // ------------------- Step 2: Load commitment C and randomness r -------------------
    HVC hvc(10); // Initialize HVC instance
    pairing_t& pairing_hvc = hvc.GetPairing();

    element_t C, r;
    element_init_G1(C, pairing_hvc);
    element_init_Zr(r, pairing_hvc);

    if (!load_element_G1_compressed("../File/Commit/C.dat", C)) {
        std::cerr << "Failed to load commitment C\n";
        return;
    }
    if (!load_element_Zr("../File/Commit/r.dat", r)) {
        std::cerr << "Failed to load randomness r\n";
        return;
    }

    // ------------------- Step 3: Load tag files -------------------
    std::vector<std::string> tag_contents;
    fs::path tag_dir = "../File/Tag";

    for (const auto &entry : fs::directory_iterator(tag_dir)) {
        if (!entry.is_regular_file()) continue;
        std::string data;
        if (!read_file_binary(entry.path().string(), data)) {
            std::cerr << "Warning: failed to read tag file " << entry.path() << std::endl;
            continue;
        }
        tag_contents.push_back(std::move(data));
    }

    if (tag_contents.empty()) {
        std::cerr << "No tag files found.\n";
        return;
    }

    // Convert tags into Zr elements
    size_t n_tags = tag_contents.size();
    element_t* m = new element_t[n_tags];
    for (size_t i = 0; i < n_tags; ++i) {
        element_init_Zr(m[i], pairing_hvc);
        element_from_hash(m[i], (void*)tag_contents[i].data(), tag_contents[i].size());
    }

    // ------------------- Step 4: Load proofs for query indices -------------------
    std::vector<size_t> query_indices = {1, 5, 7, 9};
    element_t Lambda_agg;
    element_init_G1(Lambda_agg, pairing_hvc);
    element_set1(Lambda_agg); // Initialize aggregated proof

    for (size_t idx : query_indices) {
        fs::path proof_path = "../File/Proof/Lambda_i_" + std::to_string(idx) + ".dat";
        element_t Lambda_i;
        element_init_G1(Lambda_i, pairing_hvc);

        if (!load_element_G1_compressed(proof_path.string(), Lambda_i)) {
            std::cerr << "Failed to load proof " << proof_path << std::endl;
            continue;
        }

        // Aggregate all proofs by group multiplication
        element_mul(Lambda_agg, Lambda_agg, Lambda_i);
        element_clear(Lambda_i);
    }

    // ------------------- Step 5: Verify aggregate proof -------------------
    bool valid = true;
    for (size_t idx : query_indices) {
        if (!hvc.verify(C, m[idx], Lambda_agg, idx)) {
            valid = false;
            break;
        }
    }

    if (valid)
        std::cout << "[+] Aggregate proof verified successfully.\n";
    else
        std::cerr << "[-] Aggregate proof verification failed.\n";

    // ------------------- Step 6: Decrypt corresponding files -------------------
    fs::path cipher_dir = "../File/Cipher";
    fs::path out_dir = "../File/BatchQuery";
    fs::create_directories(out_dir);

    std::vector<fs::path> cipher_files;
    for (const auto &entry : fs::directory_iterator(cipher_dir)) {
        if (entry.is_regular_file())
            cipher_files.push_back(entry.path());
    }

    for (size_t idx : query_indices) {
        if (idx >= cipher_files.size()) {
            std::cerr << "Query index out of range: " << idx << std::endl;
            continue;
        }

        // Attempt to decrypt the corresponding file
        if (decrypt_file_from_dirs(cipher_files[idx], tag_dir, out_dir, key)) {
            std::cout << "[+] File decrypted: " << cipher_files[idx].filename() << std::endl;
        } else {
            std::cerr << "[-] Failed to decrypt file " << cipher_files[idx].filename() << std::endl;
        }
    }

    // ------------------- Step 7: Cleanup -------------------
    for (size_t i = 0; i < n_tags; ++i) element_clear(m[i]);
    delete[] m;
    element_clear(C);
    element_clear(r);
    element_clear(Lambda_agg);
    element_clear(k_dek);
}