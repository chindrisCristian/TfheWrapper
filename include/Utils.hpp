#pragma once

#include <tfhe/tfhe.h>
#include <boost/thread/barrier.hpp>

class Utils {
public:

    #pragma region Addition circuit
private:
    static void AddBit(LweSample* const& sum, LweSample* const& carryOut, LweSample* const& aux, const LweSample* const& a, const LweSample* const& b, LweSample* const& carryIn, const TFheGateBootstrappingCloudKeySet* const& cloudKey);
public:
    static void FullAdderCircuit(LweSample* const& result, const LweSample* const& a, const LweSample* const& b, int bitNumber, const TFheGateBootstrappingCloudKeySet* const& cloudKey);

    #pragma endregion

    #pragma region Multiplication circuit
private:
    static void AndOperation(LweSample* const& result, const LweSample* const& ai, const LweSample* const& b, const int& bitNumber, const TFheGateBootstrappingCloudKeySet* const& cloudKey);
    static void PartialMultiplication(LweSample** const& result, const LweSample* const& a, const LweSample* const& bCopy, const TFheGateBootstrappingCloudKeySet* const& cloudKey, const int& threadId, const int& bitNumber, boost::barrier& syncBarr);
public:
    static void MultiplicationCircuit(LweSample* const& result, const LweSample* const& a, const LweSample* const& b, int bitNumber, const TFheGateBootstrappingCloudKeySet* const& cloudKey);


    static int Decrypt(const LweSample* const& c, int bitnr);
    #pragma endregion

public:
    static void CipherCopy(LweSample* const& destination, const LweSample* const& source, const int& bitNumber, const TFheGateBootstrappingCloudKeySet* const& cloudKey);
};