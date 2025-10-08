#pragma once

#include <pbc/pbc.h>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <filesystem>
#include <string>
#include <iomanip>
#include <sstream>

using namespace std;
namespace fs = std::filesystem;

// ============================================================================
//                           Configuration Constants
// ============================================================================
static constexpr int KEY_LEN = 32;            // AES-256 key length in bytes
static constexpr int IV_LEN = 12;             // Recommended IV size for AES-GCM
static constexpr int TAG_LEN = 16;            // Authentication tag length (128 bits)
static constexpr int PBKDF2_ITER = 100000;    // Example iteration count for PBKDF2 key derivation

// ============================================================================
//                           Global PBC Parameters
// ============================================================================
pairing_t pairing;    // Global pairing object
element_t g, h;       // Public system generators (h may be initialized later)

// ============================================================================
//                           System Initialization
// ============================================================================
/**
 * @brief Initialize system parameters and pairing.
 * 
 * This function loads pairing parameters from the specified file, 
 * initializes the pairing, and generates a random generator g ∈ G1.
 */
void sysInitial()
{
    cout << "*********************************System Initialization********************************" << endl;
    const std::string param_file = "../Param/a.param";

    // -------------------- Load pairing parameters --------------------
    char param[1024];
    std::ifstream file(param_file, std::ios::binary);
    if (!file)
    {
        throw std::runtime_error("Failed to open parameter file: " + param_file);
    }

    size_t count = file.readsome(param, sizeof(param));
    if (count == 0)
    {
        throw std::runtime_error("Failed to read parameter file: " + param_file);
    }

    // Initialize pairing using the loaded parameter buffer
    pairing_init_set_buf(pairing, param, count);

    // -------------------- Initialize public generators --------------------
    element_init_G1(g, pairing);
    element_random(g); // Random generator in G1

    cout << "System initialization finished!" << endl;
}

// ============================================================================
//                           Element Serialization
// ============================================================================

/**
 * @brief Save a G1 element to a file in string format.
 * 
 * The element is written in base 10 textual representation.
 * 
 * @param filename  Output file path
 * @param g1_elem   G1 element to be saved
 * @return true     If successfully written
 * @return false    On failure
 */
bool save_element_G1(const char* filename, element_t g1_elem)
{
    // Open file for writing
    FILE *fp = fopen(filename, "w");
    if (!fp)
    {
        cerr << "Error: cannot open " << filename << " for writing" << endl;
        return false;
    }

    // Write the G1 element as a string (base 10)
    if (element_out_str(fp, 10, g1_elem) == -1)
    {
        cerr << "Error: failed to write G1 element to " << filename << endl;
        fclose(fp);
        return false;
    }

    fclose(fp);
    cout << "G1 element successfully saved to " << filename << endl;

    // Note: Do not clear g1_elem here — the caller manages its lifecycle
    return true;
}

/**
 * @brief Load a G1 element from a text file.
 * 
 * The function reads the element as a base-10 string, trims whitespace,
 * and reconstructs the G1 element from that string.
 * 
 * @param path  Input file path
 * @param e     Output element to be initialized and loaded
 * @return true If successfully loaded
 * @return false On failure
 */
bool Load_element_G1(const string &path, element_t &e)
{
    // Initialize G1 element under the global pairing
    element_init_G1(e, pairing);

    // Open the file
    ifstream fin(path);
    if (!fin.is_open())
    {
        cerr << "Error: cannot open " << path << endl;
        return false;
    }

    // Read entire file content into a string
    string elem_str((istreambuf_iterator<char>(fin)),
                    istreambuf_iterator<char>());
    fin.close();

    // Trim leading and trailing whitespace
    elem_str.erase(0, elem_str.find_first_not_of(" \n\r\t"));
    elem_str.erase(elem_str.find_last_not_of(" \n\r\t") + 1);

    // Parse element from the string
    if (element_set_str(e, elem_str.c_str(), 10) == 0)
    {
        cerr << "Error: failed to parse G1 element from file." << endl;
        return false;
    }

    element_printf("Loaded G1 element: %B\n", e);
    return true;
}


// ============================================================================
//                            Load Zr Element
// ============================================================================
/**
 * @brief Load a Zr element from a file.
 * 
 * The element is read from a text file containing its decimal string form.
 * 
 * @param path  Path to the input file
 * @param e     Output Zr element to be initialized and loaded
 * @return true If successfully loaded
 * @return false On failure
 */
bool Load_element_Zr(const string &path, element_t &e)
{
    // Initialize Zr element
    element_init_Zr(e, pairing);

    // Open file for reading
    ifstream fin(path);
    if (!fin.is_open())
    {
        cerr << "Error: cannot open " << path << endl;
        return false;
    }

    // Read numeric string representation of the element
    string k_str;
    fin >> k_str;
    fin.close();

    // Parse element from string
    if (element_set_str(e, k_str.c_str(), 10) == 0)
    {
        cerr << "Error: failed to parse Zr element from file." << endl;
        return false;
    }

    // Optional debug output
    element_printf("Loaded Zr element: %B\n", e);
    return true;
}

// ============================================================================
//                              Digital Signature
// ============================================================================
/**
 * @brief Generate a digital signature using a secret key.
 * 
 * The input `hash` should already be computed externally (e.g., SHA-256).
 * Signature is computed as sig = H(hash)^secret_key over G1.
 * 
 * @param hash         Precomputed message hash string
 * @param secret_key   Secret key element in Zr
 * @return string      Signature (string representation of G1 element)
 */
string Sign(const std::string &hash, element_t secret_key)
{
    element_t h, sig;
    element_init_G1(h, pairing);
    element_init_G1(sig, pairing);

    // Map hash to a point in G1
    element_from_hash(h, (void *)hash.c_str(), hash.size());

    // Compute signature: sig = h^secret_key
    element_pow_zn(sig, h, secret_key);

    // Convert element to string for storage
    char buffer[1024];
    element_snprint(buffer, sizeof(buffer), sig);

    element_clear(h);
    element_clear(sig);
    return std::string(buffer);
}

/**
 * @brief Verify a digital signature using the public key.
 * 
 * Verifies if e(sig, g) == e(H(hash), public_key)
 * 
 * @param hash        Message hash (same as used in Sign)
 * @param signature   Signature string (G1 element)
 * @param public_key  Public key element in G1
 * @return true       If signature is valid
 * @return false      Otherwise
 */
bool Verify(const std::string &hash, const std::string &signature, element_t public_key)
{
    element_t h, sig, temp1, temp2;
    element_init_G1(h, pairing);
    element_init_G1(sig, pairing);
    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);

    // Debug output for verification process
    element_printf("The public key is %B\n", public_key);
    cout << "The hash is " << hash << endl;
    cout << "The signature is " << signature << endl;
    element_printf("The generator is %B\n", g);

    // Compute bilinear pairings
    pairing_apply(temp1, sig, g, pairing);           // temp1 = e(sig, g)
    element_printf("The temp1 is %B\n", temp1);
    pairing_apply(temp2, h, public_key, pairing);    // temp2 = e(h, public_key)
    element_printf("The temp2 is %B\n", temp2);

    bool result = (element_cmp(temp1, temp2) == 0);

    element_clear(h);
    element_clear(sig);
    element_clear(temp1);
    element_clear(temp2);

    return result;
}

// ============================================================================
//                           File String I/O Utilities
// ============================================================================
/**
 * @brief Save a string to a binary file.
 * 
 * @param data  String data to save
 * @param path  Output file path
 * @return true If written successfully
 * @return false On failure
 */
bool save_string_to_file(const string &data, const string &path)
{
    ofstream fout(path, ios::binary);
    if (!fout.is_open())
    {
        cerr << "Error: cannot open " << path << " for writing." << endl;
        return false;
    }

    fout.write(data.data(), data.size());
    fout.close();

    cout << "String saved to " << path << endl;
    return true;
}

/**
 * @brief Load a string from a binary file.
 * 
 * @param path  Input file path
 * @param data  Output string
 * @return true If successfully loaded
 * @return false On failure
 */
bool load_string_from_file(const string &path, string &data)
{
    ifstream fin(path, ios::binary);
    if (!fin.is_open())
    {
        cerr << "Error: cannot open " << path << " for reading." << endl;
        return false;
    }

    // Read the entire file content into memory
    fin.seekg(0, ios::end);
    size_t size = fin.tellg();
    fin.seekg(0, ios::beg);

    data.resize(size);
    fin.read(&data[0], size);
    fin.close();

    cout << "String loaded from " << path << endl;
    return true;
}

// ============================================================================
//                       Element Serialization (Binary Form)
// ============================================================================
/**
 * @brief Save a generator or key element to a binary file.
 * 
 * @param filename Output file name
 * @param key      Element to be saved
 */
void save_gen_to_file(const std::string &filename, element_t &key)
{
    std::ofstream file(filename, std::ios::binary);
    if (!file)
    {
        throw std::runtime_error("Failed to open file for writing: " + filename);
    }

    int key_size = element_length_in_bytes(key);
    std::vector<unsigned char> buffer(key_size);
    element_to_bytes(buffer.data(), key);
    file.write(reinterpret_cast<const char *>(buffer.data()), key_size);
}

/**
 * @brief Load a generator or key element from a binary file.
 * 
 * @param filename Input file name
 * @param key      Element to be loaded
 */
void load_gen_from_file(const std::string &filename, element_t &key)
{
    std::ifstream file(filename, std::ios::binary);
    if (!file)
    {
        throw std::runtime_error("Failed to open file for reading: " + filename);
    }

    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<unsigned char> buffer(size);
    file.read(reinterpret_cast<char *>(buffer.data()), size);
    element_from_bytes(key, buffer.data());
}

// ============================================================================
// Convert binary data to a hex string
// ============================================================================
std::string to_hex(const std::vector<unsigned char>& v) {
    std::ostringstream oss;
    for (unsigned char c : v)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    return oss.str();
}

// ============================================================================
// Print all pending OpenSSL error messages
// ============================================================================
void handle_openssl_errors() {
    ERR_print_errors_fp(stderr);
}

// ============================================================================
// Read the entire file into a vector<unsigned char>
// ============================================================================
bool read_file_all(const fs::path& p, std::vector<unsigned char>& out) {
    std::ifstream ifs(p, std::ios::binary);
    if (!ifs) return false;

    ifs.seekg(0, std::ios::end);
    auto size = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    if (size <= 0) { out.clear(); return true; }
    out.resize((size_t)size);
    ifs.read((char*)out.data(), size);
    return !!ifs;
}

// ============================================================================
// Write a binary buffer to a file
// ============================================================================
bool write_file_all(const fs::path& p, const std::vector<unsigned char>& data) {
    std::ofstream ofs(p, std::ios::binary);
    if (!ofs) return false;
    ofs.write((const char*)data.data(), data.size());
    return !!ofs;
}

// ============================================================================
// AES-256-GCM Encryption
// Inputs : plaintext, aad, key (32 bytes)
// Outputs: ciphertext, iv (IV_LEN bytes), tag (TAG_LEN bytes)
// ============================================================================
bool aes_gcm_encrypt(const std::vector<unsigned char>& plaintext,
                     const std::vector<unsigned char>& aad,
                     const std::vector<unsigned char>& key,
                     std::vector<unsigned char>& iv_out,
                     std::vector<unsigned char>& ciphertext_out,
                     std::vector<unsigned char>& tag_out)
{
    bool ok = false;
    EVP_CIPHER_CTX* ctx = nullptr;
    int len = 0, outlen = 0;

    if (key.size() != KEY_LEN) {
        std::cerr << "Key length must be " << KEY_LEN << " bytes\n";
        return false;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { handle_openssl_errors(); return false; }

    iv_out.resize(IV_LEN);
    if (RAND_bytes(iv_out.data(), IV_LEN) != 1) { handle_openssl_errors(); goto cleanup; }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) { handle_openssl_errors(); goto cleanup; }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr) != 1) { handle_openssl_errors(); goto cleanup; }
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv_out.data()) != 1) { handle_openssl_errors(); goto cleanup; }

    if (!aad.empty()) {
        if (EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), (int)aad.size()) != 1) { handle_openssl_errors(); goto cleanup; }
    }

    ciphertext_out.resize(plaintext.size());
    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx, ciphertext_out.data(), &len, plaintext.data(), (int)plaintext.size()) != 1) { handle_openssl_errors(); goto cleanup; }
        outlen = len;
    }

    if (EVP_EncryptFinal_ex(ctx, ciphertext_out.data() + outlen, &len) != 1) { handle_openssl_errors(); goto cleanup; }
    outlen += len;
    ciphertext_out.resize(outlen);

    tag_out.resize(TAG_LEN);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag_out.data()) != 1) { handle_openssl_errors(); goto cleanup; }

    ok = true;

cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// ============================================================================
// AES-256-GCM Decryption
// Inputs : ciphertext, aad, key, iv, tag
// Outputs: plaintext_out
// ============================================================================
bool aes_gcm_decrypt(const std::vector<unsigned char>& ciphertext,
                     const std::vector<unsigned char>& aad,
                     const std::vector<unsigned char>& key,
                     const std::vector<unsigned char>& iv,
                     const std::vector<unsigned char>& tag,
                     std::vector<unsigned char>& plaintext_out)
{
    bool ok = false;
    EVP_CIPHER_CTX* ctx = nullptr;
    int len = 0, outlen = 0;

    if (key.size() != KEY_LEN) { std::cerr << "Key length error\n"; return false; }
    if (iv.size() != IV_LEN) { std::cerr << "IV length error\n"; return false; }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { handle_openssl_errors(); return false; }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) { handle_openssl_errors(); goto cleanup; }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr) != 1) { handle_openssl_errors(); goto cleanup; }
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) { handle_openssl_errors(); goto cleanup; }

    if (!aad.empty()) {
        if (EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), (int)aad.size()) != 1) { handle_openssl_errors(); goto cleanup; }
    }

    plaintext_out.resize(ciphertext.size());
    if (!ciphertext.empty()) {
        if (EVP_DecryptUpdate(ctx, plaintext_out.data(), &len, ciphertext.data(), (int)ciphertext.size()) != 1) { handle_openssl_errors(); goto cleanup; }
        outlen = len;
    }

    // Set the expected authentication tag before finalization
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag.size(), (void*)tag.data()) != 1) { handle_openssl_errors(); goto cleanup; }

    if (EVP_DecryptFinal_ex(ctx, plaintext_out.data() + outlen, &len) != 1) {
        std::cerr << "Decryption failed: authentication tag mismatch\n";
        goto cleanup;
    }
    outlen += len;
    plaintext_out.resize(outlen);

    ok = true;
cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// ============================================================================
// Encrypt a single file: plaintext → ciphertext + tag
// ============================================================================
bool encrypt_file_to_dirs(const fs::path& in_path, const fs::path& out_dir, const fs::path& tag_dir, const std::vector<unsigned char>& key) {
    std::vector<unsigned char> plaintext;
    if (!read_file_all(in_path, plaintext)) { std::cerr << "Failed to read " << in_path << "\n"; return false; }

    std::string filename = in_path.filename().string();
    std::vector<unsigned char> aad(filename.begin(), filename.end());

    std::vector<unsigned char> iv, ciphertext, tag;
    if (!aes_gcm_encrypt(plaintext, aad, key, iv, ciphertext, tag)) {
        std::cerr << "Encryption failed for " << in_path << "\n";
        return false;
    }

    // Combine IV + ciphertext into one buffer
    std::vector<unsigned char> outbuf;
    outbuf.reserve(iv.size() + ciphertext.size());
    outbuf.insert(outbuf.end(), iv.begin(), iv.end());
    outbuf.insert(outbuf.end(), ciphertext.begin(), ciphertext.end());

    fs::create_directories(out_dir);
    fs::create_directories(tag_dir);

    fs::path out_file = out_dir / filename;
    fs::path tag_file = tag_dir / (filename + ".tag");

    if (!write_file_all(out_file, outbuf)) { std::cerr << "Failed to write ciphertext " << out_file << "\n"; return false; }
    if (!write_file_all(tag_file, tag)) { std::cerr << "Failed to write tag " << tag_file << "\n"; return false; }

    return true;
}

// ============================================================================
// Decrypt a single file using the ciphertext and its tag
// ============================================================================
bool decrypt_file_from_dirs(const fs::path& cipher_path, const fs::path& tag_dir, const fs::path& out_dir, const std::vector<unsigned char>& key) {
    std::vector<unsigned char> inbuf;
    if (!read_file_all(cipher_path, inbuf)) { std::cerr << "Failed to read ciphertext " << cipher_path << "\n"; return false; }
    if ((int)inbuf.size() < IV_LEN) { std::cerr << "Ciphertext too short: " << cipher_path << "\n"; return false; }

    std::string filename = cipher_path.filename().string();
    fs::path tag_file = tag_dir / (filename + ".tag");

    std::vector<unsigned char> tag;
    if (!read_file_all(tag_file, tag)) { std::cerr << "Failed to read tag " << tag_file << "\n"; return false; }
    if ((int)tag.size() != TAG_LEN) { std::cerr << "Tag length incorrect for " << tag_file << "\n"; return false; }

    std::vector<unsigned char> iv(inbuf.begin(), inbuf.begin() + IV_LEN);
    std::vector<unsigned char> ciphertext(inbuf.begin() + IV_LEN, inbuf.end());

    std::vector<unsigned char> aad(filename.begin(), filename.end());
    std::vector<unsigned char> plaintext;

    if (!aes_gcm_decrypt(ciphertext, aad, key, iv, tag, plaintext)) {
        std::cerr << "Decryption/auth failed for " << cipher_path << "\n";
        return false;
    }

    fs::create_directories(out_dir);
    fs::path out_file = out_dir / filename;

    if (!write_file_all(out_file, plaintext)) { std::cerr << "Failed to write decrypted file " << out_file << "\n"; return false; }
    return true;
}

// ============================================================================
// Encrypt up to `max_files` files in a folder
// ============================================================================
bool encrypt_folder(const fs::path& in_dir, const fs::path& out_dir, const fs::path& tag_dir, const std::vector<unsigned char>& key, size_t max_files) {
    if (!fs::exists(in_dir) || !fs::is_directory(in_dir)) { std::cerr << "Input directory invalid\n"; return false; }

    size_t processed = 0;
    for (auto& entry : fs::directory_iterator(in_dir)) {
        if (processed >= max_files) break;
        if (!entry.is_regular_file()) continue;
        if (!encrypt_file_to_dirs(entry.path(), out_dir, tag_dir, key)) return false;
        ++processed;
    }
    std::cout << "Encrypted " << processed << " files from " << in_dir << " -> " << out_dir << "\n";
    return true;
}

// ============================================================================
// Decrypt all files in a folder using tag files from tag_dir
// ============================================================================
bool decrypt_folder(const fs::path& cipher_dir, const fs::path& tag_dir, const fs::path& out_dir, const std::vector<unsigned char>& key) {
    if (!fs::exists(cipher_dir) || !fs::is_directory(cipher_dir)) { std::cerr << "Cipher directory invalid\n"; return false; }

    size_t processed = 0;
    for (auto& entry : fs::directory_iterator(cipher_dir)) {
        if (!entry.is_regular_file()) continue;
        if (!decrypt_file_from_dirs(entry.path(), tag_dir, out_dir, key)) return false;
        ++processed;
    }
    std::cout << "Decrypted " << processed << " files from " << cipher_dir << " -> " << out_dir << "\n";
    return true;
}

// ============================================================================
// Read a text or binary file into a std::string
// ============================================================================
bool read_file_to_string(const std::string &path, std::string &out) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) return false;
    out.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return true;
}

bool read_file_binary(const std::string &path, std::string &out) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;
    std::ostringstream oss;
    oss << ifs.rdbuf();
    out = oss.str();
    return true;
}

// ============================================================================
// Save and Load PBC Elements (G1, Zr)
// ============================================================================

// Save G1 element in compressed form
bool save_element_G1_compressed(const std::string &path, element_t &e) {
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;
    int len = element_length_in_bytes_compressed(e);
    std::vector<unsigned char> buf(len);
    element_to_bytes_compressed(buf.data(), e);
    ofs.write(reinterpret_cast<const char*>(buf.data()), len);
    return !!ofs;
}

// Save Zr element to file
bool save_element_Zr(const std::string &path, element_t &e) {
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;
    int len = element_length_in_bytes(e);
    std::vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), e);
    ofs.write(reinterpret_cast<const char*>(buf.data()), len);
    return !!ofs;
}

// Load G1 element (compressed) from file
bool load_element_G1_compressed(const std::string &path, element_t &e) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;
    std::vector<unsigned char> buf((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    if (buf.empty()) return false;
    element_from_bytes_compressed(e, buf.data());
    return true;
}

// Load Zr element from file
bool load_element_Zr(const std::string &path, element_t &e) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;
    std::vector<unsigned char> buf((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    if (buf.empty()) return false;
    element_from_bytes(e, buf.data());
    return true;
}