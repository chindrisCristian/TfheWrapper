#pragma region Constructor / destructor

template <typename T>
EncryptedArray<T>::EncryptedArray(const TFheGateBootstrappingCloudKeySet* cloudKey)
    : _cloudKey(cloudKey), _data()
{
}

#pragma endregion

#pragma region Public methods

template <typename T>
int EncryptedArray<T>::ImportData(std::string fileName)
{
    FILE* fIn = fopen(fileName.c_str(), "rb");
    if(fIn == NULL)
        return 1;
    int elements;
    fscanf(fIn, "%d", &elements);
    for(int i = 0; i < elements; i++)
    {
        Ciphertext<T> aux(_cloudKey);
        aux.Import(fIn);
        _data.push_back(aux);
    }
}

#pragma endregion