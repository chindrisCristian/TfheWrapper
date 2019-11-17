#pragma region Constructor and destructor
template <typename T>
Ciphertext<T>::Ciphertext(const TFheGateBootstrappingCloudKeySet* cloudKey, bool isTemp)
{
    _isTemp = isTemp;
    _cloudKey = cloudKey;
    _arraySize = sizeof(T) * 8;
    _encData = new_gate_bootstrapping_ciphertext_array(_arraySize, _cloudKey->params);
}

template <typename T>
Ciphertext<T>::~Ciphertext()
{
    if(_encData != nullptr && !_isTemp)
    {
        delete_gate_bootstrapping_ciphertext_array(_arraySize, _encData);
        _encData = nullptr;
    }
}

#pragma endregion

#pragma region Encrypt / Decrypt
template <typename T>
void Ciphertext<T>::Encrypt(const T in, const TFheGateBootstrappingSecretKeySet* secretKey)
{
    for(int i = 0; i < _arraySize; i++)
        bootsSymEncrypt(_encData + i, (in >> i) & 1, secretKey);
}

template <typename T>
T Ciphertext<T>::Decrypt(const TFheGateBootstrappingSecretKeySet* secretKey){
    T out = 0;
    int ai;
    for(int i = 0; i < _arraySize; i++){
        ai = bootsSymDecrypt(_encData + i, secretKey);
        out |= (ai << i);
    }
    return out;
}

#pragma endregion

#pragma region Operators overloading
template <typename T>
Ciphertext<T> Ciphertext<T>::operator+(const Ciphertext<T>& obj)
{
    Ciphertext<T> result(obj._cloudKey, true);
    Utils::FullAdderCircuit(result._encData, this->_encData, obj._encData, this->_arraySize, this->_cloudKey);
    return result;
}

template <typename T>
Ciphertext<T> Ciphertext<T>::operator+=(const Ciphertext<T>& obj)
{
    LweSample* result = new_gate_bootstrapping_ciphertext_array(this->_arraySize, this->_cloudKey->params);
    Utils::FullAdderCircuit(result, this->_encData, obj._encData, this->_arraySize, this->_cloudKey);
    delete_gate_bootstrapping_ciphertext_array(this->_arraySize, this->_encData);
    this->_encData = result;
    return *this;
}

template <typename T>
Ciphertext<T> Ciphertext<T>::operator*(const Ciphertext<T>& obj)
{
    Ciphertext<T> result(obj._cloudKey, true);
    Utils::MultiplicationCircuit(result._encData, this->_encData, obj._encData, this->_arraySize, this->_cloudKey);
    return result;
}

#pragma endregion