#include <iostream>
#include <armadillo>
#include <chrono>
#include <omp.h>
//#define ARMA_USE_OPENMP

using namespace std;
using namespace arma;
using namespace std::chrono;

void readFile(string name, mat *data);
int main(int argc, char const *argv[]){
    high_resolution_clock::time_point s;
    duration<double> diff;
    for (int j = 2; j <= 64 ; j = j * 2) {
        uword d = j;       // dimensionality
        uword N = 2000000;   // number of vectors
        mat data(d, N);//, fill::randu
        string name;
        name = to_string(d);
        readFile(name, &data);
        //cout<<data<<endl;
        mat means;
        printf("d %d\n", d);
        for (int i = 1; i <= 6; ++i) {
            s = high_resolution_clock::now();
            //means, data, k, seed_mode, n_iter, print_mode
            if (kmeans(means, data, int(pow(2, i)), random_subset, 1, true) == false)
                cout << "clustering failed" << endl;
            diff = high_resolution_clock::now() - s;
            printf("K %d Time(s) %lf \n", int(pow(2, i)), diff.count());
        }
        means.print("means:");
    }
    return 0;
}

void readFile(string name, mat* data){
    ifstream file;
    double *ptr = (*data).begin();
    file.open (name+".txt");
    if (!file.is_open()) return;
    string word;
    while (file >> word){
        *ptr = double (stoi(word));
        ptr++;
    }
}