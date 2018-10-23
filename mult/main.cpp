#include <iostream>
#include <chrono>
using namespace std::chrono;
#define N 256
#define MIN(A,B) (((A)<(B))?(A):(B))

void Mult(float **c, float **a, float **b){
    for (int k = 0; k < N; k++){
        for (int i = 0; i < N; i++){
            c[k][i] = 0;
            for (int j = 0; j < N; j++){
                c[k][i] += a[k][j] * b[j][i];
            }
        }
    }
}

void Tiled_Mult(float **c, float **a, float **b, int tile_size){
    float sum;
    for (int ii = 0; ii<N; ii+=tile_size) {
        for (int jj = 0; jj<N; jj+=tile_size) {
            for(int kk = 0; kk<N; kk+=tile_size) {
                for (int i = ii; i < MIN(ii+tile_size,N); i++) {
                    for (int j = jj; j < MIN(jj+tile_size,N); j++) {
                        sum = 0;
                        for (int k = kk; k < MIN(kk+tile_size,N); k++) {
                            sum += a[i][k] * b[k][j];
                        }
                        c[i][j]+= sum;
                    }
                }
            }
        }
    }
}

void Initialize(float **M){
    srand(time(NULL));
    for (int i = 0; i < N; ++i) {
        for (int j = 0; j < N; ++j) {
            M[i][j] = (float)rand()/(float)(RAND_MAX) * (rand()%100);
        }
    }
}

void Show(float **M){
    for (int i = 0; i < N; ++i) {
        for (int j = 0; j < N; ++j) {
            printf("%.2f ", M[i][j]);
        }
        printf("\n");
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    int mode = 1;
    int tile_size = 4;
    high_resolution_clock::time_point s;
    duration<double> diff;
    if(argc == 2)
        mode = atoi(argv[1]); // escolha da função

    else if(argc ==3){
        mode = atoi(argv[1]);
        tile_size = atoi(argv[2]); // escolha do tamanho do tiled
    }

    //float A [N][N];// = {{5.0, 3.0, 6.0, 7.0},{9.0, 3.0, 5.0, 3.0},{8.0, 8.0, 3.0, 9.0},{6.0, 9.0, 5.0, 1.0}};
    //float B [N][N];// = {{7.0, 5.0, 1.0, 4.0},{4.0, 8.0, 9.0, 2.0},{7.0, 4.0, 2.0, 1.0},{3.0, 5.0, 8.0, 9.0}};
    //float C [N][N];// = {{0.0, 0.0, 0.0, 0.0},{0.0, 0.0, 0.0, 0.0},{0.0, 0.0, 0.0, 0.0},{0.0, 0.0, 0.0, 0.0}};

    float **A = (float **) malloc(N * sizeof(float *));
    float **B = (float **) malloc(N * sizeof(float *));
    float **C = (float **) malloc(N * sizeof(float *));
    for (int i = 0; i < N; ++i) {
        A[i] = (float *) malloc(N * sizeof(float));
        B[i] = (float *) malloc(N * sizeof(float));
        C[i] = (float *) malloc(N * sizeof(float));
    }

    Initialize(A);
    Initialize(B);
    printf("%.2f %.2f %.2f\n",A[0][0], B[0][0], C[0][0]);

    if(mode == 0){
        s = high_resolution_clock::now();
        Tiled_Mult(C, A, B, tile_size);
        diff =  high_resolution_clock::now() - s;
    }

    else if(mode == 1) {
        s = high_resolution_clock::now();
        Mult(C, A, B);
        diff =  high_resolution_clock::now() - s;
    }

    else{
        printf("Parameter error");
        return 0;
    }

    printf("\n%lf time(s) \n",diff.count());
    printf("%.2f %.2f %.2f\n",A[0][0], B[0][0], C[0][0]);
    //Show(C);
    return 0;
}