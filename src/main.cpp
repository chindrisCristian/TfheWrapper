#include <iostream>
#include <fstream>
#include <time.h>
#include "KeyManager.hpp"
#include "Ciphertext.hpp"

using namespace std;

void GetInput(const char* const& fileName, int* const& a, int* const& b, int& n)
{
    ifstream fin(fileName);
    fin >> n;
    for(int i = 0; i < n ;i++)
    {
        fin >> *(a + i) >> *(b + i);
    }
    fin.close();
}

int main(int argc, char** argv) {
    /*int a[1000], b[1000], n;
    GetInput(argv[1], a, b, n);
    KeyManager& km = KeyManager::GetInstance();
    if(km.ImportSecretKey("../key.secret"))
        return 1;
    Ciphertext c1(32, km.GetCloudKey()), c2(32, km.GetCloudKey());
    uint32_t value_dec;
    ofstream fout(argv[2]);
    for(int i = 0; i < n; i++){
        c1.Encrypt(a[i], km.GetSecretKey());
        c2.Encrypt(b[i], km.GetSecretKey());
        Ciphertext product = c1 * c2;
        value_dec = product.Decrypt(km.GetSecretKey());
        fout << value_dec << endl;
    }
    fout.close();*/
    /*ofstream fout(argv[1]), fout2(argv[2]);
    fout << 100 << endl;
    fout2 << 100 << endl;
    int a, b;
    for(int i = 0; i < 100; i++)
    {
        a = rand() % 1000;
        b = rand() % 1000;
        fout << a << " " << b << endl;
        fout2 << a * b << endl;
    }
    fout.close();
    fout2.close();*/
    ifstream fin(argv[1]), fin2(argv[2]);
    int n;
    fin >> n;
    int a, b;
    for(int i = 0; i < n; i++){
        fin >> a;
        fin2 >> b;
        if(a != b){
            cout << "Eroare la linia " << i + 2;
            break;
        }
    }

    return 0;
}