#pragma once

#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <thread>
#include <iostream>
#include "KeyManager.hpp"
#include "Utils.hpp"

using namespace std;

template <typename T>
class Ciphertext {
    LweSample*                              _encData;
    int                                     _arraySize;
    const TFheGateBootstrappingCloudKeySet* _cloudKey;
public:
    Ciphertext(const TFheGateBootstrappingCloudKeySet* cloudKey);
    Ciphertext(const Ciphertext& obj) = delete;
    Ciphertext(Ciphertext&& obj);
    ~Ciphertext();

    void Encrypt(const T in, const TFheGateBootstrappingSecretKeySet* secretKey);
    T Decrypt(const TFheGateBootstrappingSecretKeySet* secretKey);

    int Export(FILE* file);
    int Import(FILE* file);

    Ciphertext operator+(const Ciphertext& obj);
    Ciphertext operator+=(const Ciphertext& obj);
    Ciphertext operator*(const Ciphertext& obj);
    Ciphertext operator=(const Ciphertext& obj) = delete;
    Ciphertext operator=(Ciphertext&& obj);

};

#include "../src/Ciphertext.tpp"