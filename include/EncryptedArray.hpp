#pragma once

#include "Ciphertext.hpp"
#include <list>
#include <string>

template<typename T>
class EncryptedArray {
    std::list<Ciphertext<T>>                _data;
    const TFheGateBootstrappingCloudKeySet* _cloudKey;
public:
    EncryptedArray(const TFheGateBootstrappingCloudKeySet* cloudKey);
    EncryptedArray(const EncryptedArray&) = delete;
    EncryptedArray operator=(const EncryptedArray&) = delete;
    ~EncryptedArray() = default;

    int ImportData(std::string fileName);

};

#include "../src/EncryptedArray.tpp"