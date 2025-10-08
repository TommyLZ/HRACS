#pragma once

#include <pbc/pbc.h>
#include <iostream>
#include <vector>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <unistd.h>
#include <libgen.h>
#include <filesystem>
#include <fstream>

using namespace std;
namespace fs = filesystem;

/**
 * @brief Save an array of Zr elements to a binary file
 * @param filename The output file path
 * @param z Pointer to an array of elements
 */
void saveZToFile(const std::string& filename, element_t* z) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file for writing: " + filename);
    }

    for (int i = 0; i <= 10; ++i) {
        // Convert each element to bytes
        size_t len = element_length_in_bytes(z[i]);
        std::vector<unsigned char> buffer(len);
        element_to_bytes(buffer.data(), z[i]);

        file.write(reinterpret_cast<char*>(buffer.data()), len);
    }
    file.close();
}

/**
 * @brief Load an array of Zr elements from a binary file
 * @param filename The input file path
 * @param z Pointer to an array of elements
 */
void loadZFromFile(const std::string& filename, element_t* z) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file for reading: " + filename);
    }

    for (int i = 0; i <= 10; ++i) {
        size_t len = element_length_in_bytes(z[i]);
        std::vector<unsigned char> buffer(len);

        file.read(reinterpret_cast<char*>(buffer.data()), len);
        if (file.gcount() != len) {
            throw std::runtime_error("Failed to read z_i from file");
        }

        element_from_bytes(z[i], buffer.data());
    }
    file.close();
}

/**
 * @brief Hash-based Homomorphic Verifiable Commitment (HVC) class
 */
class HVC {
private:
    pairing_t pairing;        // Pairing object
    element_t* z;             // Private values z_i
    element_t* h;             // Public elements h_i
    element_t** h_ij;         // Public elements h_{i,j}
    element_t g;              // Generator g
    int size;                 // Number of elements
    string g_file_path = "../Key/g.dat";
    string z_file = "../Key/z_i.dat";
    string param_file = "../Param/a.param";

public:
    /**
     * @brief Constructor: Initialize pairing, generator, and HVC elements
     * @param n Number of elements in the commitment
     */
    HVC(int n): size(n) {
        // Load pairing parameters from file
        char param[1024];
        std::ifstream file(param_file, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Failed to open parameter file: " + param_file);
        }
        size_t count = file.readsome(param, sizeof(param));
        if (count == 0) {
            throw std::runtime_error("Failed to read parameter file: " + param_file);
        }
        pairing_init_set_buf(pairing, param, count);

        element_init_G1(g, pairing);

        // Load or generate generator g
        if (fs::exists(g_file_path)) {
            load_gen_from_file(g_file_path, g);
            // element_printf("********The initialization of g is %B\n", g);
        } else {
            element_random(g);
            save_gen_to_file(g_file_path, g);
        }

        // Allocate memory for z and h
        z = new element_t[n + 1];
        h = new element_t[n + 1];
        h_ij = new element_t*[n + 1];

        for (int i = 0; i <= n; ++i) {
            element_init_Zr(z[i], pairing);
            element_init_G1(h[i], pairing);
            h_ij[i] = new element_t[n + 1];
            for (int j = 0; j <= n; ++j) {
                element_init_G1(h_ij[i][j], pairing);
            }
        }

        // Try to load z_i from file
        try {
            cout << "Loaded z_i from file." << endl;
            loadZFromFile(z_file, z);
            setup(n);
        } catch (const std::runtime_error&) {
            cout << "Failed to load z_i from file. Generating new z_i..." << endl;
            for (int i = 0; i <= n; ++i) {
                element_random(z[i]);
            }
            setup(n);
            saveZToFile(z_file, z);  // Save newly generated z_i
            cout << "Saved new z_i to file." << endl;
        }
    }

    /**
     * @brief Destructor: Clear all elements and pairing
     */
    ~HVC() {
        element_clear(g);

        for (int i = 0; i <= size; ++i) {
            element_clear(z[i]);
            element_clear(h[i]);
            for (int j = 0; j <= size; ++j) {
                if (i != j) element_clear(h_ij[i][j]);
            }
            delete[] h_ij[i];
        }

        delete[] z;
        delete[] h;
        delete[] h_ij;

        pairing_clear(pairing);
    }

    // ------------------- Accessor -------------------
    pairing_t& getPairing() { return pairing; }
    pairing_t& GetPairing() { return pairing; }

    // ------------------- Setup function -------------------
    void setup(int n) {
        // Compute h_i = g^{z_i}
        for (int i = 0; i <= n; ++i) {
            element_pow_zn(h[i], g, z[i]);
        }

        // Compute h_{i,j} = g^{z_i * z_j} for i != j
        for (int i = 0; i <= n; ++i) {
            for (int j = 0; j <= n; ++j) {
                if (i != j) {
                    element_t tmp;
                    element_init_Zr(tmp, pairing);
                    element_mul(tmp, z[i], z[j]);
                    element_pow_zn(h_ij[i][j], g, tmp);
                    element_clear(tmp);
                }
            }
        }
        cout << "HVC.Setup completed." << endl;
    }

    // ------------------- Commitment function -------------------
    void commit(element_t* m, int n, element_t& C, element_t& r) {
        element_init_G1(C, pairing);
        element_init_Zr(r, pairing);
        element_random(r);
        element_set1(C);

        // Compute C = Π h[i]^m[i]
        for (size_t i = 0; i < n; ++i) {
            element_t tmp;
            element_init_G1(tmp, pairing);
            element_pow_zn(tmp, h[i], m[i]);
            element_mul(C, C, tmp);
            element_clear(tmp);
        }

        // Multiply by h[n-1]^r
        element_t h_r;
        element_init_G1(h_r, pairing);
        element_pow_zn(h_r, h[n-1], r);
        element_mul(C, C, h_r);
        element_clear(h_r);

        cout << "HVC.Com completed." << endl;
    }

    // ------------------- Open function -------------------
    void open(element_t* m, int n, int i, element_t& r, element_t& Lambda_i) {
        element_init_G1(Lambda_i, pairing);
        element_set1(Lambda_i);

        // Multiply Λ_i = Π_{j != i} h_ij[i][j]^m[j]
        for (size_t j = 0; j < n; ++j) {
            if (j != i) {
                element_t tmp;
                element_init_G1(tmp, pairing);
                element_pow_zn(tmp, h_ij[i][j], m[j]);
                element_mul(Lambda_i, Lambda_i, tmp);
                element_clear(tmp);
            }
        }

        // Multiply by h_ij[i][n-1]^r
        element_t h_in_plus1;
        element_init_G1(h_in_plus1, pairing);
        element_pow_zn(h_in_plus1, h_ij[i][n-1], r);
        element_mul(Lambda_i, Lambda_i, h_in_plus1);
        element_clear(h_in_plus1);

        cout << "HVC.Open completed." << endl;
    }

    // ------------------- Verification function -------------------
    bool verify(element_t& C, element_t& m_i, element_t& Lambda_i, int i) {
        element_t left, right, tmp;
        element_init_GT(left, pairing);
        element_init_GT(right, pairing);
        element_init_G1(tmp, pairing);

        element_pow_zn(tmp, h[i], m_i);
        element_div(tmp, C, tmp);
        pairing_apply(left, tmp, h[i], pairing);
        pairing_apply(right, Lambda_i, g, pairing);

        bool result = !element_cmp(left, right);

        element_clear(left);
        element_clear(right);
        element_clear(tmp);

        return result;
    }

    // ------------------- Homomorphic combination of commitments -------------------
    void comHom(element_t& C1, element_t& C2, element_t& C_out) {
        element_init_G1(C_out, pairing);
        element_mul(C_out, C1, C2); // Combine commitments
        cout << "HVC.ComHom completed." << endl;
    }

    // ------------------- Homomorphic combination of opened values -------------------
    void openHom(element_t& Lambda_j1, element_t& Lambda_j2, element_t& Lambda_j_out) {
        element_init_G1(Lambda_j_out, pairing);
        element_mul(Lambda_j_out, Lambda_j1, Lambda_j2); // Combine opened values
        cout << "HVC.OpenHom completed." << endl;
    }
};
