#pragma once

#include <string>
#include <fstream>
#include <random>
#include <iostream>
#include "Ciphertext.hpp"
#include "KeyManager.hpp"

using namespace std;

enum OperationType{
    Addition,
    Multiplication
};

template<typename T>
class StressTest {
    string          _contentFN;
    string          _encContentFN;
    string          _resultFN;
    string          _encResultFN;
    string          _decResultFN;
    int             _elementCount;
public:
    StressTest(string contentFileName, string encContent, string result, string encResult, string decResult, int elementCount);
    ~StressTest() = default;

    void            RecreateContent(int elementCount = -1);
    void            ComputePlain(OperationType operation);
    void            EncryptContent(string secretKeyFN);
    void            ComputeEncrypted(string cloudKeyFN, OperationType operation);
    void            DecryptContent(string secretKeyFN);
    void            Compare();
    void            RunDefault(OperationType operation, string secretKeyFN, string cloudKeyFN);

private:
    void            SeedFile();
};

#include "../src/StressTest.tpp"