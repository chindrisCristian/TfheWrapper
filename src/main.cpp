#include "StressTest.hpp"
#include "EncryptedArray.hpp"

using namespace std;

int main(int argc, char** argv) {
    /*int elementCount = atoi(argv[1]);
    StressTest<uint16_t> st("tests/16_bit/content", "tests/16_bit/encContent", "tests/16_bit/result", "tests/16_bit/encResult", "tests/16_bit/decResult", elementCount);
    st.RunDefault(OperationType::Multiplication, "../key.secret", "../key.cloud");*/

    KeyManager& km = KeyManager::GetInstance();
    km.ImportSecretKey("keys/key120.secret");

    Ciphertext<int16_t> enc1(km.GetCloudKey()), enc2(km.GetCloudKey());

    srand(time(NULL));

    int p1 = rand() % (INT8_MAX), p2 = rand() % (INT8_MAX), pr = p1 * p2;
    enc1.Encrypt(p1, km.GetSecretKey());
    enc2.Encrypt(p2, km.GetSecretKey());

    Ciphertext<int16_t> enc_res = enc1 * enc2;
    int dec_p = enc_res.Decrypt(km.GetSecretKey());

    cout << p1 << " * " << p2 << " = " << pr << endl;
    cout << "Expected result: " << dec_p << endl;
     
    //EncryptedArray<int16_t> array(km.GetCloudKey());
    return 0;
}