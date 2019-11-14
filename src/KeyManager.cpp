#include "KeyManager.hpp"
#include <random>

#include <iostream>

KeyManager* KeyManager::_instance = nullptr;

#pragma region Constructor and destructor

KeyManager::KeyManager() {
    _secretKey = nullptr;
    _cloudKey = nullptr;
    _parameterSet = nullptr;
}

KeyManager::~KeyManager(){
    if(_secretKey != nullptr){
        delete_gate_bootstrapping_secret_keyset(_secretKey);
        _secretKey = nullptr;
        _cloudKey = nullptr;
        _parameterSet = nullptr;
    }
    if(_cloudKey != nullptr){
        delete_gate_bootstrapping_cloud_keyset(_cloudKey);
        _cloudKey = nullptr;
        _parameterSet = nullptr;
    }
}

#pragma endregion

#pragma region Creating and destroying the instance

KeyManager& KeyManager::GetInstance() {
    if(_instance == nullptr)
        _instance = new KeyManager();
    return *_instance;
}

void KeyManager::Destroy(){
    if(_instance != nullptr)
    {
        delete _instance;
        _instance = nullptr;
    }
}

#pragma endregion

#pragma region Public methods

void KeyManager::GenerateKeySet(int minimumLambda){
    // Generate the parameters for this cryptosystem.
    _parameterSet = new_default_gate_bootstrapping_parameters(minimumLambda);

    // Generate a random key based on a random seed.
    srand(time(NULL));
    uint32_t seed[] = {rand(), rand(), rand()};
    tfhe_random_generator_setSeed(seed, 3);

    // Generate the key.
    _secretKey = new_random_gate_bootstrapping_secret_keyset(_parameterSet);
    _cloudKey = (TFheGateBootstrappingCloudKeySet*)&_secretKey->cloud;
}

int KeyManager::ExportSecretKey(string fileName) const {
    if(_secretKey == nullptr)
        return -1;
    FILE* fOut = fopen(fileName.c_str(), "wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(fOut, _secretKey);
    fclose(fOut);
    return 0;
}

int KeyManager::ExportCloudKey(string fileName) const {
    if(_cloudKey == nullptr)
        return -1;
    FILE* fOut = fopen(fileName.c_str(), "wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(fOut, _cloudKey);
    fclose(fOut);
    return 0;
}

int KeyManager::ImportSecretKey(string fileName){
    FILE* fIn = fopen(fileName.c_str(), "rb");
    if(fIn == NULL)
        return -1;
    if(_secretKey != nullptr)
        delete_gate_bootstrapping_secret_keyset(_secretKey);
    _secretKey = new_tfheGateBootstrappingSecretKeySet_fromFile(fIn);
    _cloudKey = (TFheGateBootstrappingCloudKeySet*)&_secretKey->cloud;
    _parameterSet = (TFheGateBootstrappingParameterSet*)_secretKey->params;
    fclose(fIn);
    
    return 0;
}

int KeyManager::ImportCloudKey(string fileName){
    FILE* fIn = fopen(fileName.c_str(), "rb");
    if(fIn == NULL)
        return -1;
    if(_cloudKey != nullptr)
        delete_gate_bootstrapping_cloud_keyset(_cloudKey);
    _cloudKey = new_tfheGateBootstrappingCloudKeySet_fromFile(fIn);
    _parameterSet = (TFheGateBootstrappingParameterSet*)_cloudKey->params;
    return 0;
}

const TFheGateBootstrappingCloudKeySet* KeyManager::GetCloudKey() const {
    return _cloudKey;
}

const TFheGateBootstrappingSecretKeySet* KeyManager::GetSecretKey() const {
    return _secretKey;
}

const TFheGateBootstrappingParameterSet* KeyManager::GetParameterSet() const {
    return _parameterSet;
}

#pragma endregion