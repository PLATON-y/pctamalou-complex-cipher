# pctamalou-complex-cipher


# PCTamalou Complex Cipher – Implémentation C / C Implementation

## 🇫🇷 Français

### Vue d’ensemble

PCTamalou Complex Cipher est une bibliothèque cryptographique expérimentale écrite en C pur. Elle implémente :

- **Hachage** (construction sponge) avec une permutation basée sur une intégrale de contour discrète utilisant des racines de l’unité et des valeurs de la fonction zêta de Riemann.
- **Fonction de dérivation de clé** (KDF) avec itérations configurables et un paramètre de « durée » (pour la *forward secrecy*).
- **Chiffrement authentifié** (AEAD) utilisant un chiffrement par flux basé sur un réseau de Feistel rapide et un MAC polynomial (similaire à Poly1305) sur le corps fini F_p² (p = 2²⁵⁵ - 19).
- **Fonction MAC** autonome.

Ce code est **éducatif et expérimental**. Il n’a pas été audité et ne doit **pas** être utilisé pour protéger des données sensibles. Il s’adresse aux développeurs curieux, aux mathématiciens et à celles et ceux qui s’intéressent aux constructions cryptographiques alternatives.

### Fonctionnalités

- Opérations déterministes et en temps constant pour les parties critiques (comparaison MAC).
- Inversion par lots (Montgomery trick) pour la performance.
- Aucune dépendance externe (uniquement la bibliothèque standard C).
- API adaptée pour l’intégration dans d’autres projets ou le *binding* avec Python (ctypes).

### Compilation


make          # construit la bibliothèque partagée et le programme de test
make test     # exécute les tests unitaires
make bench    # exécute les benchmarks de performance
make clean    # supprime les fichiers générés


### Tests et performances


$ make test
Hash déterministe                  ... ✓
Hash sensible à la casse           ... ✓
Avalanche                           ... Avalanche : 54.1% bits changés ✓
KDF déterministe                   ... ✓
Encrypt/Decrypt basique             ... ✓
Mauvaise clé → exception MAC        ... ✓
Ciphertext modifié → exception MAC  ... ✓
Message vide                        ... ✓
4096 octets aléatoires              ... ✓
MAC déterministe                    ... ✓
MAC sensible aux données            ... ✓
11 tests passed, 0 failed



$ make bench
Hash 1 KB     : 0.15 MB/s
Hash 64 KB    : 0.17 MB/s
Encrypt 1 KB  : 0.34 MB/s
Encrypt 64 KB : 11.29 MB/s
KDF (10k it)  : 16.39 s


### Utilisation


#include "pctamalou_core.c" // ou lien avec la bibliothèque

int main() {
    uint8_t key[32] = {0};
    uint8_t nonce[16] = {0};
    const char *plain = "Message secret";
    uint8_t cipher[256], decrypted[256];
    size_t clen = PCT_encrypt(key, 32, nonce, (uint8_t*)plain, strlen(plain), cipher);
    int64_t plen = PCT_decrypt(key, 32, cipher, clen, decrypted);
    if (plen >= 0) printf("OK: %.*s\n", (int)plen, decrypted);
    return 0;
}


### Licence

GPLv3 (voir fichier `LICENSE`).



## 🇬🇧 English

### Overview

**PCTamalou Complex Cipher** is an experimental cryptographic library written in pure C. It implements:

- **Hashing** (sponge construction) with a permutation based on a discrete contour integral using roots of unity and values of the Riemann zeta function.
- **Key derivation function** (KDF) with configurable iterations and a “duration” parameter (for forward secrecy).
- **Authenticated encryption** (AEAD) using a fast Feistel-based stream cipher plus a polynomial MAC (similar to Poly1305) over the finite field F_p² (p = 2^255 - 19).
- **Standalone MAC** function.

This code is **educational and experimental**. It has not been audited and must **not** be used to protect real sensitive data. It is intended for curious developers, mathematicians, and those interested in alternative cryptographic constructions.

### Features

- Deterministic, constant‑time operations for critical parts (MAC comparison).
- Batch inversion (Montgomery trick) for performance.
- No external dependencies (only standard C library).
- API suitable for embedding in other projects or binding with Python (ctypes).

### Building


make          # build shared library and test program
make test     # run unit tests
make bench    # run performance benchmarks
make clean    # remove generated files
```

### Tests & Performance


$ make test
Hash déterministe                  ... ✓
Hash sensible à la casse           ... ✓
Avalanche                           ... Avalanche : 54.1% bits changés ✓
KDF déterministe                   ... ✓
Encrypt/Decrypt basique             ... ✓
Mauvaise clé → exception MAC        ... ✓
Ciphertext modifié → exception MAC  ... ✓
Message vide                        ... ✓
4096 octets aléatoires              ... ✓
MAC déterministe                    ... ✓
MAC sensible aux données            ... ✓
11 tests passed, 0 failed



$ make bench
Hash 1 KB     : 0.15 MB/s
Hash 64 KB    : 0.17 MB/s
Encrypt 1 KB  : 0.34 MB/s
Encrypt 64 KB : 11.29 MB/s
KDF (10k it)  : 16.39 s


### Usage


#include "pctamalou_core.c" // or link with the library

int main() {
    uint8_t key[32] = {0};
    uint8_t nonce[16] = {0};
    const char *plain = "Secret message";
    uint8_t cipher[256], decrypted[256];
    size_t clen = PCT_encrypt(key, 32, nonce, (uint8_t*)plain, strlen(plain), cipher);
    int64_t plen = PCT_decrypt(key, 32, cipher, clen, decrypted);
    if (plen >= 0) printf("OK: %.*s\n", (int)plen, decrypted);
    return 0;
}


### License

GPLv3 (see `LICENSE` file).

