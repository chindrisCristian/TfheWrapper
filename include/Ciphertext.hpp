#pragma once

#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <thread>
#include <iostream>
#include "Utils.hpp"

using namespace std;

template <typename T>
class Ciphertext {
    bool                                    _isTemp;
    LweSample*                              _encData;
    int                                     _arraySize;
    const TFheGateBootstrappingCloudKeySet* _cloudKey;
public:
    Ciphertext(const TFheGateBootstrappingCloudKeySet* cloudKey, bool isTemp = false);
    ~Ciphertext();

    void Encrypt(const T in, const TFheGateBootstrappingSecretKeySet* secretKey);
    T Decrypt(const TFheGateBootstrappingSecretKeySet* secretKey);

    Ciphertext operator+(const Ciphertext& obj);
    Ciphertext operator+=(const Ciphertext& obj);
    Ciphertext operator*(const Ciphertext& obj);


    void SetAsTemporary(){
        _isTemp = true;
    }
};

#include "../src/Ciphertext.tpp"