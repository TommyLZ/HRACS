#pragma once

#include "PublicParam.h"
#include "HVC.h"
#include <filesystem>
#include <vector>
#include <iostream>
#include <string>
#include <algorithm> // for sort
#include <openssl/sha.h>

namespace fs = std::filesystem;
using namespace std;

/**
 * @brief Single Query Phase
 * 
 * This function performs the following main tasks:
 *   1. Load the DEK (Data Encryption Key) derived from the stored seed.
 *   2. Load the commitment C and randomness r.
 *   3. Read all tag files and hash them into elements in Zr.
 *   4. Load the corresponding proof Λ_i for the target query index.
 *   5. Decrypt the corresponding ciphertext file using the derived DEK.
 *   6. Clean up all cryptographic elements and memory.
 * 
 * @param query_index  The index of the file to be queried (default = 2).
 */
void SingleQuery(size_t query_index = 2)
{
    cout << "*************************** Single Query Phase ***************************" << endl;

    // =========================================================================
    // Step 1: Load and derive DEK (Data Encryption Key)
    // =========================================================================
    string seed;
    if (!load_string_from_file("../Storage/seed.txt", seed)) {
        cerr << "Failed to load seed.txt" << endl;
        return;
    }

    // Derive DEK-specific seed and map to Zr
    string seed_dek = seed + "DEK";
    element_t k_dek;
    element_init_Zr(k_dek, pairing);
    element_from_hash(k_dek, (void*)seed_dek.c_str(), seed_dek.length());

    // Convert k_dek into bytes
    int len = element_length_in_bytes(k_dek);
    vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), k_dek);

    // Derive 256-bit AES key from k_dek using SHA-256
    vector<unsigned char> key(32);
    SHA256(buf.data(), buf.size(), key.data());

    // =========================================================================
    // Step 2: Load commitment C and randomness r
    // =========================================================================
    HVC hvc(10); // Dummy initialization to get the correct pairing context
    pairing_t& pairing_hvc = hvc.GetPairing();

    element_t C, r;
    element_init_G1(C, pairing_hvc);
    element_init_Zr(r, pairing_hvc);

    if (!load_element_G1_compressed("../File/Commit/C.dat", C)) {
        cerr << "Failed to load commitment C" << endl;
        return;
    }
    if (!load_element_Zr("../File/Commit/r.dat", r)) {
        cerr << "Failed to load randomness r" << endl;
        return;
    }

    // =========================================================================
    // Step 3: Load all tag files from directory
    // =========================================================================
    vector<string> tag_contents;
    fs::path tag_dir = "../File/Tag";

    for (const auto &entry : fs::directory_iterator(tag_dir)) {
        if (!entry.is_regular_file()) continue;

        string data;
        if (!read_file_binary(entry.path().string(), data)) {
            cerr << "Warning: failed to read tag file " << entry.path() << endl;
            continue;
        }
        tag_contents.push_back(move(data));
    }

    if (tag_contents.empty()) {
        cerr << "No tag files found." << endl;
        return;
    }

    // Sort tags by file name to ensure query_index consistency
    sort(tag_contents.begin(), tag_contents.end());

    size_t n = tag_contents.size();
    element_t* m = new element_t[n];

    // Map each tag to Zr: m_i = H(tag_i)
    for (size_t i = 0; i < n; ++i) {
        element_init_Zr(m[i], pairing_hvc);
        element_from_hash(m[i], (void*)tag_contents[i].data(), tag_contents[i].size());
    }

    // =========================================================================
    // Step 4: Load proof Λ_i corresponding to the query index
    // =========================================================================
    element_t Lambda_i;
    element_init_G1(Lambda_i, pairing_hvc);

    fs::path proof_path = "../File/Proof/Lambda_i_" + to_string(query_index) + ".dat";
    if (!load_element_G1_compressed(proof_path.string(), Lambda_i)) {
        cerr << "Failed to load proof for query " << query_index << endl;
        return;
    }

    cout << "[+] Proof loaded: " << proof_path << endl;

    // =========================================================================
    // Step 5: Decrypt the corresponding ciphertext file
    // =========================================================================
    fs::path cipher_dir = "../File/Cipher";
    fs::path out_dir = "../File/SingleQuery";
    fs::create_directories(out_dir);

    vector<fs::path> cipher_files;
    for (const auto &entry : fs::directory_iterator(cipher_dir)) {
        if (entry.is_regular_file())
            cipher_files.push_back(entry.path());
    }

    // Sort ciphertext files by file name for consistent indexing
    sort(cipher_files.begin(), cipher_files.end());

    if (query_index >= cipher_files.size()) {
        cerr << "Query index out of range" << endl;
    } else {
        // Perform AES-GCM decryption using derived key and tag
        if (decrypt_file_from_dirs(cipher_files[query_index], tag_dir, out_dir, key)) {
            cout << "[+] File decrypted: " << cipher_files[query_index].filename() << endl;
        } else {
            cerr << "[-] Failed to decrypt file " << cipher_files[query_index].filename() << endl;
        }
    }

    // =========================================================================
    // Step 6: Cleanup and release allocated memory
    // =========================================================================
    for (size_t i = 0; i < n; ++i)
        element_clear(m[i]);
    delete[] m;

    element_clear(C);
    element_clear(r);
    element_clear(Lambda_i);
    element_clear(k_dek);
}