#pragma once

#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>

class Ciphertext {
    bool                                    _isTemp;
    LweSample*                              _encData;
    int                                     _arraySize;
    const TFheGateBootstrappingCloudKeySet* _cloudKey;
public:
    Ciphertext(int arraySize, const TFheGateBootstrappingCloudKeySet* cloudKey, bool isTemp = false);
    ~Ciphertext();

    void Encrypt(const uint32_t in, const TFheGateBootstrappingSecretKeySet* secretKey);
    uint32_t Decrypt(const TFheGateBootstrappingSecretKeySet* secretKey);

    void SetAsTemporary(){
        _isTemp = true;
    }

    Ciphertext operator+(const Ciphertext& obj);
    Ciphertext operator+=(const Ciphertext& obj);
    Ciphertext operator*(const Ciphertext& obj);

};