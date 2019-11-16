#include "Utils.hpp"

#include <boost/thread.hpp>

#include <iostream>
#include <KeyManager.hpp>

boost::mutex mtx;

using namespace std;

#pragma region Addition circuit 

void Utils::AddBit(LweSample* const& sum, LweSample* const& carryOut, LweSample* const& aux, const LweSample* const& a, const LweSample* const& b, LweSample* const& carryIn, const TFheGateBootstrappingCloudKeySet* const& cloudKey){
    // Sum bit.
    bootsXOR(aux, a, b, cloudKey);
    bootsXOR(sum, aux, carryIn, cloudKey);
    // Carry out bit.
    bootsMUX(carryOut, aux, carryIn, a, cloudKey);
}

void Utils::FullAdderCircuit(LweSample* const& result, const LweSample* const& a, const LweSample* const& b, int bitNumber, const TFheGateBootstrappingCloudKeySet* const& cloudKey){
    // We need a carry in, a carry out, and one auxiliar space for resolving
    // this operation on a multithreaded way.
    LweSample* temp = new_gate_bootstrapping_ciphertext_array(3, cloudKey->params);
    // Set the first sum and carry out.
    bootsXOR(result, a, b, cloudKey);   // The first sum bit.
    bootsAND(temp, a, b, cloudKey);     // The first carry out bit.
    // Calculate for the rest of the bits.
    for(int i = 1; i < bitNumber; i++){
        Utils::AddBit(result + i,!(i % 2)? temp : temp + 1, temp + 2, a + i, b + i, !(i % 2)? temp + 1 : temp, cloudKey);
    }
    // Cleanup.
    delete_gate_bootstrapping_ciphertext_array(3, temp);
}

#pragma endregion

#pragma region Multiplication circuit

void Utils::AndOperation(LweSample* const& result, const LweSample* const& ai, const LweSample* const& b, const int& bitNumber, const TFheGateBootstrappingCloudKeySet* const& cloudKey){
    for(int i = 0; i < bitNumber; i++)
        bootsAND(result + i, ai, b + i, cloudKey);
}

void Utils::PartialMultiplication(LweSample** const& result, const LweSample* const& a, const LweSample* const& bCopy, const TFheGateBootstrappingCloudKeySet* const& cloudKey, const int& threadId, const int& bitNumber, boost::barrier& syncBarr){
    // Create the partial results.
    if(threadId)
        result[threadId] = new_gate_bootstrapping_ciphertext_array(bitNumber, cloudKey->params);
    result[bitNumber - threadId - 1] = new_gate_bootstrapping_ciphertext_array(bitNumber, cloudKey->params);
    // Initiliaze the AND operations.
    LweSample* temp = new_gate_bootstrapping_ciphertext_array(bitNumber, cloudKey->params);
    Utils::AndOperation(result[threadId], a + threadId, bCopy + bitNumber - threadId, bitNumber, cloudKey);
    Utils::AndOperation(result[bitNumber - threadId - 1], a + bitNumber - threadId - 1, bCopy + threadId + 1, bitNumber, cloudKey);
    int step;

    /*mtx.lock();
    cout << threadId << ": ";
    Decrypt(result[threadId], bitNumber);
    cout << bitNumber - threadId - 1 << ": ";
    Decrypt(result[bitNumber - threadId - 1], bitNumber);
    cout << endl;
    mtx.unlock();*/

    for(step = 1; step < bitNumber; step *= 2){
        if((threadId * step < bitNumber / 2) && (threadId < bitNumber / step - threadId - 1)){
                Utils::FullAdderCircuit(temp, result[threadId] + bitNumber / step - threadId - 1, result[bitNumber / step - threadId - 1] + bitNumber / step - threadId - 1, bitNumber - bitNumber / step + threadId + 1, cloudKey);
                Utils::CipherCopy(result[threadId] + bitNumber / step - threadId - 1, temp, bitNumber - bitNumber / step + threadId + 1, cloudKey);

                /*mtx.lock();
                cout << threadId << " " << step << ": ";
                Decrypt(result[threadId], bitNumber);
                cout << endl;
                mtx.unlock();*/

        }
        syncBarr.wait();
    }
    // Cleanup.
    delete_gate_bootstrapping_ciphertext_array(bitNumber, temp);
    if(threadId)
        delete_gate_bootstrapping_ciphertext_array(bitNumber, result[threadId]);
    delete_gate_bootstrapping_ciphertext_array(bitNumber, result[bitNumber - threadId - 1]);
}

void Utils::MultiplicationCircuit(LweSample* const& result, const LweSample* const& a, const LweSample* const& b, int bitNumber, const TFheGateBootstrappingCloudKeySet* const& cloudKey){
    // Create a copy of b in a 2 * size(b) having MSBs bit number 0
    // and then the bits of b. 
    LweSample* bCopy = new_gate_bootstrapping_ciphertext_array(2 * bitNumber, cloudKey->params);
    for(int i = 0; i < bitNumber; i++)
        bootsCONSTANT(bCopy + i, 0, cloudKey);
    for(int i = bitNumber; i < 2 * bitNumber; i++)
        bootsCOPY(bCopy + i, b - bitNumber + i, cloudKey);
    // Create the partial results.
    LweSample** partialResults = new LweSample*[bitNumber];
    partialResults[0] = result;
    boost::thread threads[bitNumber / 2];
    boost::barrier syncBarr(bitNumber / 2);
    for(int i = 0; i < bitNumber / 2; i++)
    {
        threads[i] = boost::thread(Utils::PartialMultiplication, partialResults, a, bCopy, cloudKey, i, bitNumber, boost::ref(syncBarr));
    }

    for(int i = 0; i < bitNumber / 2; i++)
        threads[i].join();
    
    // Cleanup.
    delete[] partialResults;
    delete_gate_bootstrapping_ciphertext_array(2 * bitNumber, bCopy);
}

#pragma endregion

void Utils::CipherCopy(LweSample* const& destination, const LweSample* const& source, const int& bitNumber, const TFheGateBootstrappingCloudKeySet* const& cloudKey){
    for(int i = 0; i < bitNumber; i++)
        bootsCOPY(destination + i, source + i, cloudKey);
}

int Utils::Decrypt(const LweSample* const& c, int bitnr){
    uint32_t out = 0;
    int ai;
    for(int i = 0; i < bitnr; i++){
        ai = bootsSymDecrypt(c + i, KeyManager::GetInstance().GetSecretKey());
        cout << ai << " ";
        out |= (ai << i);
    }
    cout << endl;
    return out;
}