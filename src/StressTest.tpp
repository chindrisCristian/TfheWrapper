template<typename T>
StressTest<T>::StressTest(string contentFileName, string encContent, string result, string encResult, string decResult, int elementCount)
    : _contentFN(contentFileName), _encContentFN(encContent), _resultFN(result), _encResultFN(encResult), _decResultFN(decResult), _elementCount(elementCount) {
    SeedFile();
}

template <typename T>
void StressTest<T>::RecreateContent(int elementCount){
    _elementCount = (elementCount != -1)? elementCount : _elementCount;
    SeedFile();
}


template <typename T>
void StressTest<T>::SeedFile(){
    ofstream fOut(_contentFN);
    T maxValue = 2 ^ (sizeof(T) * 4);
    srand(time(NULL));
    for(int i = 0; i < _elementCount; i++)
    {
        fOut << rand() % maxValue << " " << rand() % maxValue << endl;
    }
    fOut.close();

    cout << "There has been generated " << _elementCount << " pairs of elements in the file called " << _contentFN << "." << endl;
}

template <typename T>
void StressTest<T>::ComputePlain(OperationType operation){
    ofstream fOut(_resultFN);
    ifstream fIn(_contentFN);
    T op1, op2, result;
    for(int i = 0; i < _elementCount; i++){
        fIn >> op1 >> op2;
        switch (operation)
        {
        case OperationType::Addition:
            result = op1 + op2;
            break;
        case OperationType::Multiplication:
            result = op1 * op2;
        default:
            break;
        }
        fOut << result << endl;
    }
    fIn.close();
    fOut.close();

    cout << "The file " << _resultFN << " contains the results of the operation applied on the pairs taken from " << _contentFN << "." << endl;
}

template <typename T>
void StressTest<T>::EncryptContent(string secretKeyFN){
    // Get the key manager.
    KeyManager& km = KeyManager::GetInstance();
    km.ImportSecretKey(secretKeyFN);
    ifstream fIn(_contentFN);
    T op1[_elementCount], op2[_elementCount];
    for(int i = 0; i < _elementCount; i++)
        fIn >> op1[i] >> op2[i];
    fIn.close();
    Ciphertext<T> c1(km.GetCloudKey()), c2(km.GetCloudKey());
    FILE* fOut = fopen(_encContentFN.c_str(), "wb");
    for(int i = 0; i < _elementCount; i++){
        c1.Encrypt(op1[i], km.GetSecretKey());
        c2.Encrypt(op2[i], km.GetSecretKey());
        if(c1.Export(fOut))
            return;
        if(c2.Export(fOut))
            return;
    }
    cout << "The content was encrypted and saved in " << _encContentFN << "." << endl;
    fclose(fOut);
    km.Destroy();
}

template <typename T>
void StressTest<T>::ComputeEncrypted(string cloudKeyFN, OperationType operation){
    KeyManager& km = KeyManager::GetInstance();
    km.ImportCloudKey(cloudKeyFN);
    Ciphertext<T> c1(km.GetCloudKey()), c2(km.GetCloudKey());
    FILE* fIn = fopen(_encContentFN.c_str(), "rb"), *fOut = fopen(_encResultFN.c_str(), "wb");
    for(int i = 0; i < _elementCount; i++){
        if(c1.Import(fIn))
            return;
        if(c2.Import(fIn))
            return;
        if(operation == OperationType::Multiplication){
            Ciphertext<T> cipherResult = c1 * c2;
            cipherResult.Export(fOut);
        }
        if(operation == OperationType::Addition){
            Ciphertext<T> cipherResult = c1 + c2;
            cipherResult.Export(fOut);
        }
    }
    cout << "The encrypted content was computed and saved in " << _encResultFN << "." << endl;
    fclose(fIn);
    fclose(fOut);
    km.Destroy();
}

template <typename T>
void StressTest<T>::DecryptContent(string secretKeyFN){
    // Get the key manager.
    KeyManager& km = KeyManager::GetInstance();
    km.ImportSecretKey(secretKeyFN);
    Ciphertext<T> c1(km.GetCloudKey());
    T res;
    FILE* fIn = fopen(_encResultFN.c_str(), "rb");
    ofstream fOut(_decResultFN);
    for(int i = 0; i < _elementCount; i++){
        if(c1.Import(fIn))
            return;
        res = c1.Decrypt(km.GetSecretKey());
        fOut << res << endl;
    }
    fclose(fIn);
    fOut.close();
    km.Destroy();
    cout << "The decrypted results were computed and saved in " << _decResultFN << "." << endl;
}

template <typename T>
void StressTest<T>::Compare(){
    ifstream f1(_resultFN), f2(_decResultFN);
    T val1, val2;
    for(int i = 0; i < _elementCount; i++){
        f1 >> val1;
        f2 >> val2;
        if(val1 != val2){
            cout << "The files are not equal. Different values found at line " << i + 1 << endl << endl;
            return;
        }
    }
    cout << "The files are equal! That's a good job!" << endl;
    f1.close();
    f2.close();
}

template <typename T>
void StressTest<T>::RunDefault(OperationType operation, string secretKeyFN, string cloudKeyFN){
    ComputePlain(operation);
    EncryptContent(secretKeyFN);
    ComputeEncrypted(cloudKeyFN, operation);
    DecryptContent(secretKeyFN);
    Compare();
}