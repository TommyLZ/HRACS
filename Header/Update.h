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
#include "SingleQuery.h"

extern pairing_t pairing; // only used in Upload for k_dek derivation
extern element_t g;

using namespace std;
namespace fs = std::filesystem;

void Update()
{
    // =======================
    // Step 1: Load DEK key
    // =======================
    std::string seed;
    if (!load_string_from_file("../Storage/seed.txt", seed))
    {
        std::cerr << "Failed to load seed.txt\n";
        return;
    }
    std::string seed_dek = seed + "DEK";

    element_t k_dek;
    element_init_Zr(k_dek, pairing);
    element_from_hash(k_dek, (void *)seed_dek.c_str(), seed_dek.length());

    // Derive AES-256 key
    int len = element_length_in_bytes(k_dek);
    std::vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), k_dek);
    std::vector<unsigned char> key(32);
    SHA256(buf.data(), buf.size(), key.data());

    // =======================
    // Step 2: Query old file
    // =======================
    size_t index = 2;
    SingleQuery(index);

    // =======================
    // Step 3: Encrypt new file
    // =======================
    std::string new_file_path = "../File/Update/Origin/element_" + std::to_string(index) + ".dat";
    std::vector<unsigned char> new_file_data;
    if (!read_file_all(new_file_path, new_file_data))
    {
        std::cerr << "Failed to read new file: " << new_file_path << std::endl;
        return;
    }

    std::vector<unsigned char> iv(12);
    if (RAND_bytes(iv.data(), iv.size()) != 1)
    {
        std::cerr << "Failed to generate IV\n";
        return;
    }

    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> tag;
    std::vector<unsigned char> aad;

    if (!aes_gcm_encrypt(new_file_data, aad, key, iv, ciphertext, tag))
    {
        std::cerr << "AES-GCM encryption failed\n";
        return;
    }

    std::string cipher_path = "../File/Update/Cipher/element_" + std::to_string(index) + ".dat";
    std::string tag_path = "../File/Update/Tag/element_" + std::to_string(index) + ".dat.tag";

    write_file_all(cipher_path, ciphertext);
    write_file_all(tag_path, tag);

    // =======================
    // Step 4: Compute tag difference (delta)
    // =======================
    std::vector<unsigned char> old_tag;
    std::string old_tag_path = "../File/Tag/element_" + std::to_string(index) + ".dat.tag";
    if (!read_file_all(old_tag_path, old_tag))
    {
        std::cerr << "Failed to read old tag: " << old_tag_path << std::endl;
        return;
    }

    element_t old_tag_elem, new_tag_elem, delta_tag;
    element_init_Zr(old_tag_elem, pairing);
    element_init_Zr(new_tag_elem, pairing);
    element_init_Zr(delta_tag, pairing);

    // ⚠️ 使用 element_from_hash 映射 tag 到 Zr
    element_from_hash(old_tag_elem, old_tag.data(), old_tag.size());
    element_from_hash(new_tag_elem, tag.data(), tag.size());

    element_sub(delta_tag, new_tag_elem, old_tag_elem); // delta_tag = new_tag - old_tag

    // =======================
    // Step 5: Build delta vector for HVC
    // =======================
    int n = 10;
    std::vector<element_t> delta_vec(n);

    for (int i = 0; i < n; ++i)
    {
        element_init_Zr(delta_vec[i], pairing);
        if (i == index)
        {
            element_set(delta_vec[i], delta_tag);
        }
        else
        {
            element_set0(delta_vec[i]);
        }
    }

    // =======================
    // Step 6: Update vector commitment
    // =======================
    HVC hvc(10); // HVC instance
    element_t C_old, r_old, C_delta, r_delta, C_new;
    element_init_G1(C_old, pairing);
    element_init_Zr(r_old, pairing);
    load_element_G1_compressed("../File/Commit/C.dat", C_old);
    load_element_Zr("../File/Commit/r.dat", r_old);

    // element_init_G1(C_delta, pairing);
    // element_init_Zr(r_delta, pairing);
    hvc.commit(delta_vec.data(), n, C_delta, r_delta);

    element_init_G1(C_new, pairing);
    hvc.comHom(C_old, C_delta, C_new);

    // 直接调用 save，不使用 if
    save_element_G1("../File/Update/Commit/C.dat", C_new);
    save_element_Zr("../File/Update/Commit/r.dat", r_old);

    // =======================
    // Step 7: Update proofs
    // =======================
    for (int i = 0; i < n; ++i)
    {
        element_t Lambda_i_old, Lambda_i_delta, Lambda_i_new;
        element_init_G1(Lambda_i_old, pairing);
        element_init_G1(Lambda_i_delta, pairing);
        element_init_G1(Lambda_i_new, pairing);

        std::string old_proof_path = "../File/Proof/Lambda_i_" + std::to_string(i) + ".dat";
        std::string new_proof_path = "../File/Update/Proof/Lambda_i_" + std::to_string(i) + ".dat";

        std::cout << "Processing proof file: " << old_proof_path << std::endl;

        // 尝试加载旧 proof
        if (!load_element_G1_compressed(old_proof_path, Lambda_i_old))
        {
            std::cerr << "Failed to load Lambda_i_old for index " << i << std::endl;
            element_clear(Lambda_i_old);
            element_clear(Lambda_i_delta);
            element_clear(Lambda_i_new);
            continue;
        }
        std::cout << "Loaded Lambda_i_old successfully for index " << i << std::endl;

        if (i == index)
        {
            hvc.open(delta_vec.data(), n, i, r_delta, Lambda_i_new);
            std::cout << "Generated Lambda_i_new directly for index " << i << std::endl;
        }
        else
        {
            hvc.open(delta_vec.data(), n, i, r_delta, Lambda_i_delta);
            std::cout << "Generated Lambda_i_delta for index " << i << std::endl;

            hvc.openHom(Lambda_i_old, Lambda_i_delta, Lambda_i_new);
            std::cout << "Computed Lambda_i_new via homomorphic combination for index " << i << std::endl;
        }

        if (!save_element_G1(new_proof_path.c_str(), Lambda_i_new))
        {
            std::cerr << "Failed to save Lambda_i_new for index " << i << std::endl;
            element_clear(Lambda_i_old);
            element_clear(Lambda_i_delta);
            element_clear(Lambda_i_new);
            continue;
        }
        std::cout << "Saved Lambda_i_new successfully for index " << i << std::endl;

        element_clear(Lambda_i_old);
        element_clear(Lambda_i_delta);
        element_clear(Lambda_i_new);
    }

    // =======================
    // Step 8: Clear temporary elements
    // =======================
    element_clear(old_tag_elem);
    element_clear(new_tag_elem);
    element_clear(delta_tag);

    for (int i = 0; i < n; ++i)
        element_clear(delta_vec[i]);

    element_clear(C_old);
    element_clear(C_delta);
    element_clear(C_new);
    element_clear(r_old);
    element_clear(r_delta);

    std::cout << "Update completed successfully for file index " << index << std::endl;
}
