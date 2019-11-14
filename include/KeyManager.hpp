#pragma once

#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <string>

using namespace std;

class KeyManager {

public:
    static KeyManager&                  GetInstance();
    static void                         Destroy();

    void                                GenerateKeySet(int minimumLambda);
    int                                 ExportSecretKey(string fileName) const;
    int                                 ExportCloudKey(string fileName) const;

    const TFheGateBootstrappingCloudKeySet*     GetCloudKey() const;
    const TFheGateBootstrappingSecretKeySet*    GetSecretKey() const;
    const TFheGateBootstrappingParameterSet*    GetParameterSet() const;

    int                                 ImportSecretKey(string fileName);
    int                                 ImportCloudKey(string fileName);
    
    KeyManager(KeyManager const&) = delete;
    void operator=(KeyManager const&) = delete;

private:
    KeyManager();
    ~KeyManager();

    static KeyManager*                    _instance;
    TFheGateBootstrappingSecretKeySet*    _secretKey;
    TFheGateBootstrappingCloudKeySet*     _cloudKey;
    TFheGateBootstrappingParameterSet*    _parameterSet;
};