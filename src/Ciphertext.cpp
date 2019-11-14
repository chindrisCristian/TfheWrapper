#include "Ciphertext.hpp"
#include "Utils.hpp"

#include <thread>
#include <iostream>

using namespace std;

#pragma region Constructor and destructor

Ciphertext::Ciphertext(int arraySize, const TFheGateBootstrappingCloudKeySet* cloudKey, bool isTemp)
{
    _isTemp = isTemp;
    _cloudKey = cloudKey;
    _encData = new_gate_bootstrapping_ciphertext_array(arraySize, _cloudKey->params);
    _arraySize = arraySize;
}

Ciphertext::~Ciphertext()
{
    if(_encData != nullptr && _isTemp)
    {
        delete_gate_bootstrapping_ciphertext_array(_arraySize, _encData);
        _encData = nullptr;
    }
}

#pragma endregion

#pragma region Encrypt / Decrypt

void Ciphertext::Encrypt(const uint32_t in, const TFheGateBootstrappingSecretKeySet* secretKey)
{
    for(int i = 0; i < _arraySize; i++)
        bootsSymEncrypt(_encData + i, (in >> i) & 1, secretKey);
}

uint32_t Ciphertext::Decrypt(const TFheGateBootstrappingSecretKeySet* secretKey){
    uint32_t out = 0;
    int ai;
    for(int i = 0; i < _arraySize; i++){
        ai = bootsSymDecrypt(_encData + i, secretKey);
        out |= (ai << i);
    }
    return out;
}

#pragma endregion

#pragma region Operators overloading

Ciphertext Ciphertext::operator+(const Ciphertext& obj)
{
    Ciphertext result(obj._arraySize, obj._cloudKey, true);
    Utils::FullAdderCircuit(result._encData, this->_encData, obj._encData, 32, this->_cloudKey);
    return result;
}

Ciphertext Ciphertext::operator*(const Ciphertext& obj)
{
    Ciphertext result(obj._arraySize, obj._cloudKey, true);
    Utils::MultiplicationCircuit(result._encData, this->_encData, obj._encData, 32, this->_cloudKey);
    return result;
}

Ciphertext Ciphertext::operator+=(const Ciphertext& obj)
{
    LweSample* result = new_gate_bootstrapping_ciphertext_array(32, this->_cloudKey->params);
    Utils::FullAdderCircuit(result, this->_encData, obj._encData, 32, this->_cloudKey);
    delete_gate_bootstrapping_ciphertext_array(32, this->_encData);
    this->_encData = result;
    return *this;
}

#pragma endregion