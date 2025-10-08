#pragma once

#include <cstring>
#include <iostream>
#include <pbc/pbc.h>
#include "PublicParam.h"

using namespace std;

extern pairing_t pairing;

/**
 * @brief Login Phase
 * 
 * This function performs the login process for a user identified by (identity, password).
 * It includes user authentication, server verification, key exchange, and session key derivation.
 */
void Login(string identity, string password)
{
    cout << "***********************************Login Phase*********************************" << endl;

    // === Step 1: Load the user's pseudonym rho ===
    element_t rho;
    element_init_G1(rho, pairing);
    Load_element_G1("../Storage/rho.txt", rho);

    // === Step 2: Generate random r and compute h, alpha ===
    element_t r, h, alpha;
    element_init_Zr(r, pairing);
    element_random(r);

    element_init_G1(h, pairing);
    element_init_G1(alpha, pairing);

    string psw_id_str = identity + password;

    // Hash (identity + password) to G1
    element_from_hash(h, (void *)psw_id_str.c_str(), psw_id_str.length());

    // Blindness: alpha = h^r
    element_pow_zn(alpha, h, r);

    element_printf("h = %B\n", h);
    element_printf("alpha = %B\n", alpha);

    // === Step 3: Compute beta = alpha^{k_o} ===
    element_t beta;
    element_init_G1(beta, pairing);
    element_t k_o;

    if (Load_element_Zr("../Storage/k_o.txt", k_o))
    {
        element_printf("Loaded k_o = %B\n", k_o);
    }

    element_pow_zn(beta, alpha, k_o);
    element_printf("beta = %B\n", beta);

    // === Step 4: Server authentication preparation ===
    element_t y, Y;
    element_init_Zr(y, pairing);
    element_random(y);

    element_init_G1(Y, pairing);
    element_pow_zn(Y, g, y); // Y = g^y

    element_t sk_s;
    element_init_Zr(sk_s, pairing);

    char Y_buf[1024];  // buffer for element string
    int Y_len = element_snprint(Y_buf, sizeof(Y_buf), Y);

    // Server signs Y using its secret key
    string sigma_s = Sign(string(Y_buf, Y_len), sk_s);

    // Load the server public key
    element_t pk_s;
    element_init_G1(pk_s, pairing);
    Load_element_G1("../Storage/server_public_key.txt", pk_s);

    // Verify server's signature
    if (Verify(string(Y_buf, Y_len), sigma_s, pk_s))
    {
        cout << "User authenticate server success!" << endl;
    }

    // === Step 5: Compute beta^(r^-1) ===
    element_t r_inverse;
    element_init_Zr(r_inverse, pairing);
    element_invert(r_inverse, r);

    element_t beta_r_inverse;
    element_init_G1(beta_r_inverse, pairing);
    element_pow_zn(beta_r_inverse, beta, r_inverse);

    element_printf("beta_r_inverse = %B\n", beta);

    // === Step 6: Generate high-entropy seed ===
    char beta_buf[1024];
    int len = element_snprint(beta_buf, sizeof(beta_buf), beta_r_inverse);

    // Combine password and beta_r_inverse
    string pwd_beta_invert = password + string(beta_buf, len);

    // Hash to G1 for seed generation
    element_t seed;
    element_init_G1(seed, pairing);
    element_from_hash(seed, (void *)pwd_beta_invert.c_str(), pwd_beta_invert.length());
    element_printf("high-entropy seed = %B\n", seed);

    // === Step 7: Derive user private key sk_u from seed ===
    char seed_buf[1024];
    len = element_snprint(seed_buf, sizeof(seed_buf), seed);

    string seed_sign = string(seed_buf, len) + "Sign";

    element_t sk_u;
    element_init_Zr(sk_u, pairing);
    element_from_hash(sk_u, (void*)seed_sign.c_str(), seed_sign.length());
    element_printf("the user private key sk_u = %B\n", sk_u);

    // === Step 8: Generate user's ephemeral key pair (x, X) ===
    element_t x, X;
    element_init_Zr(x, pairing);
    element_random(x);

    element_init_G1(X, pairing);
    element_pow_zn(X, g, x); // X = g^x

    char X_buf[1024];
    int X_len = element_snprint(X_buf, sizeof(X_buf), X);

    // === Step 9: User signs session data ===
    string X_Y_sigma_s = string(X_buf, X_len) + string(Y_buf, Y_len) + sigma_s;
    string sigma_u = Sign(X_Y_sigma_s, sk_u);

    // === Step 10: Compute session key on user side ===
    element_t gxy;
    element_init_G1(gxy, pairing);
    element_pow_zn(gxy, Y, x); // g^{xy}

    char gxy_buf[1024];
    int gxy_len = element_snprint(gxy_buf, sizeof(gxy_buf), gxy);

    // Combine authentication materials into session key seed
    string user_string = sigma_s + sigma_u + string(X_buf, X_len) + string(Y_buf, Y_len) + string(gxy_buf, gxy_len);

    element_t user_k_se;
    element_init_G1(user_k_se, pairing);
    element_from_hash(user_k_se, (void*)user_string.c_str(), user_string.length());
    element_printf("User: k_se= %B\n", user_k_se);

    // === Step 11: Verify signatures and establish mutual authentication ===
    char rho_buf[1024];
    int rho_len = element_snprint(rho_buf, sizeof(rho_buf), rho);

    element_t pk_u;
    element_init_G1(pk_u, pairing);
    Load_element_G1("../Storage/server_public_key.txt", pk_u);

    char pk_u_buf[1024];
    int pk_u_len = element_snprint(pk_u_buf, sizeof(pk_u_buf), pk_u);

    string rho_pk_u = string(rho_buf, rho_len) + string(pk_u_buf, pk_u_len);

    string sigma_rho;
    load_string_from_file("../Storage/sigma_rho", sigma_rho);

    // Verify both server and user signatures
    if (Verify(rho_pk_u, sigma_rho, pk_s) && Verify(X_Y_sigma_s, sigma_u, pk_u))
    {
        cout << "The signature verification success!" << endl;

        // === Step 12: Compute session key on server side ===
        element_t server_gxy;
        element_init_G1(server_gxy, pairing);
        element_pow_zn(server_gxy, X, y); // g^{xy}

        char server_gxy_buf[1024];
        int server_gxy_len = element_snprint(server_gxy_buf, sizeof(server_gxy_buf), server_gxy);

        string server_string = sigma_s + sigma_u + string(X_buf, X_len) + string(Y_buf, Y_len) + string(server_gxy_buf, server_gxy_len);

        element_t server_k_se;
        element_init_G1(server_k_se, pairing);
        element_from_hash(server_k_se, (void*)server_string.c_str(), server_string.length());
        element_printf("Server: k_se= %B\n", server_k_se);
    }
}
