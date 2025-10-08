#pragma once

#include <iostream>
#include <cstring>
#include <pbc/pbc.h>
#include "PublicParam.h"

extern pairing_t pairing;
extern element_t g;

/**
 * @brief Registration Phase
 * 
 * This function performs the registration process for a user identified by (identity, password).
 * It involves hashing, blinding, key derivation, pseudonym generation, 
 * and the creation of a user public-private key pair.
 */
void Registration(string &identity, string &password)
{
    cout << "***********************************Registration Phase*********************************" << endl;

    // === Step 1: Generate random value r and compute h, alpha ===
    element_t r, h, alpha;
    element_init_Zr(r, pairing);
    element_random(r);

    element_init_G1(h, pairing);
    element_init_G1(alpha, pairing);

    string psw_id_str = identity + password;

    // Hash (identity + password) to G1
    element_from_hash(h, (void*)psw_id_str.c_str(), psw_id_str.length());

    // Blindness: alpha = h^r
    element_pow_zn(alpha, h, r);

    element_printf("h = %B\n", h);
    element_printf("alpha = %B\n", alpha);

    // === Step 2: Compute beta = alpha^{k_o} ===
    element_t beta;
    element_init_G1(beta, pairing);
    element_t k_o;

    if (Load_element_Zr("../Storage/k_o.txt", k_o)) {
        element_printf("Loaded k_o = %B\n", k_o);
    }

    element_pow_zn(beta, alpha, k_o);
    element_printf("beta = %B\n", beta);

    // === Step 3: Compute beta^(r^-1) ===
    element_t r_inverse;
    element_init_Zr(r_inverse, pairing);
    element_invert(r_inverse, r);

    element_t beta_r_inverse;
    element_init_G1(beta_r_inverse, pairing);
    element_pow_zn(beta_r_inverse, beta, r_inverse);

    element_printf("beta_r_inverse = %B\n", beta);

    // === Step 4: High-entropy seed generation ===
    char beta_buf[1024];  // buffer for element string
    int len = element_snprint(beta_buf, sizeof(beta_buf), beta_r_inverse);

    // Concatenate password and beta_r_inverse string
    string pwd_beta_invert = password + string(beta_buf, len);

    // Hash to G1 to get the high-entropy seed
    element_t seed;
    element_init_G1(seed, pairing);
    element_from_hash(seed, (void*)pwd_beta_invert.c_str(), pwd_beta_invert.length());
    element_printf("high-entropy seed h = %B\n", seed);

    // === Step 5: Pseudonym generation ===
    char seed_buf[1024];  // buffer for element string
    len = element_snprint(seed_buf, sizeof(seed_buf), seed);

    // Combine identity with the seed to create pseudonym input
    string id_seed = identity + string(seed_buf, len);

    // Hash to G1 to derive pseudonym rho
    element_t rho;
    element_init_G1(rho, pairing);
    element_from_hash(rho, (void*)id_seed.c_str(), id_seed.length());
    element_printf("the pseudonym rho = %B\n", rho);

    // Save pseudonym to file
    save_element_G1("../Storage/rho.txt", rho);

    // === Step 6: User key generation (private/public key pair) ===
    string seed_sign = string(seed_buf, len) + "Sign";

    element_t sk_u;
    element_init_Zr(sk_u, pairing);
    element_from_hash(sk_u, (void*)seed_sign.c_str(), seed_sign.length());
    element_printf("the user private key sk_u = %B\n", sk_u);

    element_t pk_u;
    element_init_G1(pk_u, pairing); 
    element_pow_zn(pk_u, g, sk_u);
    element_printf("the user public key pk_u = %B\n", pk_u);

    // Save the public key to file
    save_element_G1("../Storage/user_public_key.txt", pk_u);

    // === Step 7: Generate server signature sigma_rho ===
    char rho_buf[1024];
    int len_rho_buf = element_snprint(rho_buf, sizeof(rho_buf), rho);

    char pk_u_buf[1024];
    int len_pk_u_buf = element_snprint(pk_u_buf, sizeof(pk_u_buf), pk_u);

    // Concatenate rho and pk_u
    string rho_pk_u = string(rho_buf, len_rho_buf) + string(pk_u_buf, len_pk_u_buf);

    element_t sk_s;
    Load_element_Zr("../Storage/server_secre_key.txt", sk_s);

    string sigma_rho = Sign(rho_pk_u, sk_s);
    cout << "The sigma_rho: " << sigma_rho << endl;

    // Save the signature to file
    save_string_to_file(sigma_rho, "../Storage/sigma_rho");

    // === Step 8: Clear sensitive elements ===
    element_clear(r);
    element_clear(h);
    element_clear(alpha);
    element_clear(r_inverse);
    element_clear(beta);
    element_clear(beta_r_inverse);
}
