#pragma once

#include <iostream>
#include <cstring>
#include <fstream>
#include <vector>
#include <sstream>
#include <filesystem>
#include <pbc/pbc.h>
#include <openssl/sha.h>
#include "PublicParam.h"
#include "HVC.h"

extern pairing_t pairing; // Used only in Upload() for k_dek derivation
extern element_t g;

using namespace std;
namespace fs = std::filesystem;

/**
 * @brief Upload Phase: Encrypts data, generates commitments and proofs.
 * 
 * This function performs the following main operations:
 *   1. Derive a data encryption key (DEK) from the stored seed.
 *   2. Encrypt original files under DEK and generate authentication tags.
 *   3. Compute commitments over the tags using the HVC scheme.
 *   4. Generate proofs corresponding to each tag for later verification.
 */
void Upload()
{
    cout << "***********************************Upload Phase*********************************" << endl;

    // =========================================================================
    // Step 1: Generate data encryption key (DEK)
    // =========================================================================
    string seed;
    load_string_from_file("../Storage/seed.txt", seed);   // Load stored seed from file
    string seed_dek = seed + "DEK";                       // Derive DEK-specific seed

    // Compute k_dek = H(seed || "DEK") ∈ Zr
    element_t k_dek;
    element_init_Zr(k_dek, pairing);
    element_from_hash(k_dek, (void *)seed_dek.c_str(), seed_dek.length());

    // Convert k_dek into bytes
    int len = element_length_in_bytes(k_dek);
    vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), k_dek);

    // Derive 256-bit AES key from k_dek using SHA-256
    vector<unsigned char> key(32);
    SHA256(buf.data(), buf.size(), key.data());

    // Encrypt original files and output ciphertext and authentication tags
    encrypt_folder("../File/Origin", "../File/Cipher", "../File/Tag", key, 10);

    // Prepare directories for commitments and proofs
    fs::path tag_dir = "../File/Tag";
    fs::path commit_dir = "../File/Commit";
    fs::path proof_dir = "../File/Proof";
    fs::create_directories(commit_dir);
    fs::create_directories(proof_dir);

    // =========================================================================
    // Step 2: Read all authentication tags for commitment
    // =========================================================================
    vector<string> tag_contents;
    for (const auto &entry : fs::directory_iterator(tag_dir))
    {
        if (!entry.is_regular_file())
            continue;

        string data;
        if (!read_file_binary(entry.path().string(), data))
        {
            cerr << "Warning: failed to read tag file " << entry.path() << endl;
            continue;
        }
        tag_contents.push_back(move(data));
    }

    if (tag_contents.empty())
    {
        cerr << "No tag files found — aborting commitment phase." << endl;
        return;
    }

    int n = static_cast<int>(tag_contents.size());
    HVC hvc(n);
    pairing_t &pairing_hvc = hvc.GetPairing();

    // =========================================================================
    // Step 3: Compute commitment C and randomness r
    // =========================================================================
    element_t *m = new element_t[n];
    for (int i = 0; i < n; ++i)
    {
        element_init_Zr(m[i], pairing_hvc);
        element_from_hash(m[i], (void *)tag_contents[i].data(), tag_contents[i].size());
    }

    element_t C, r;
    hvc.commit(m, n, C, r);

    // Save commitment C and randomness r
    fs::path C_path = commit_dir / "C.dat";
    fs::path r_path = commit_dir / "r.dat";
    save_element_G1_compressed(C_path.string(), C);
    save_element_Zr(r_path.string(), r);

    cout << "[+] Commitment saved: " << C_path << endl;
    cout << "[+] Randomness saved: " << r_path << endl;

    // Clear temporary elements for commitment
    for (int i = 0; i < n; ++i)
        element_clear(m[i]);
    delete[] m;
    element_clear(C);
    element_clear(r);

    // =========================================================================
    // Step 4: Reload commitment and randomness for proof generation
    // =========================================================================
    element_t C2, r2;
    element_init_G1(C2, pairing_hvc);
    element_init_Zr(r2, pairing_hvc);

    load_element_G1_compressed(C_path.string(), C2);
    load_element_Zr(r_path.string(), r2);

    // Reconstruct tag elements m[i] for proof generation
    element_t *m2 = new element_t[n];
    for (int i = 0; i < n; ++i)
    {
        element_init_Zr(m2[i], pairing_hvc);
        element_from_hash(m2[i], (void *)tag_contents[i].data(), tag_contents[i].size());
    }

    // =========================================================================
    // Step 5: Compute and store individual proofs for each tag
    // =========================================================================
    for (int i = 0; i < n; ++i)
    {
        element_t Lambda_i;
        element_init_G1(Lambda_i, pairing_hvc);

        // Compute proof for tag i: Λ_i = Open(C, r, m_i)
        hvc.open(m2, n, i, r2, Lambda_i);

        // Save proof Λ_i to file
        fs::path lambda_path = proof_dir / ("Lambda_i_" + to_string(i) + ".dat");
        save_element_G1_compressed(lambda_path.string(), Lambda_i);
        element_clear(Lambda_i);
    }

    cout << "[+] Proofs generated and saved for all tags." << endl;

    // =========================================================================
    // Step 6: Cleanup and memory deallocation
    // =========================================================================
    for (int i = 0; i < n; ++i)
        element_clear(m2[i]);
    delete[] m2;
    element_clear(C2);
    element_clear(r2);
    element_clear(k_dek);
}
