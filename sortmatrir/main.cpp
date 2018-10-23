#include <iostream>

#define DIM 5 // tamanho da matriz

void fillMatrix(int M[][DIM]){
    for (int i = 0; i < DIM; ++i) {
        for (int j = 0; j < DIM; ++j) {
            M[i][j] = rand()%100;// prenche com numero aleatório de 0 a 99
        }
    }
}

void printMatrix(int M[][DIM]){
    for (int i = 0; i < DIM; ++i) {
        for (int j = 0; j < DIM; ++j) {
            printf("%d ",M[i][j]);
        }
        printf("\n");
    }
    printf("\n");
}

void sortMatrix(int M[][DIM]){
    int (*pm)[DIM] = M;// ponteiro para o primeiro elemento da matriz (ponteiro para um vetor de tamnho DIM ou seja ponteiro pra uma linha da matriz)
    int *pi = (int*)pm ; // conversao de pm para 'pointeiro sequencial'
    // pm             pm+1           pm+2            pm+3
    // |               |               |               |
    // v               v               v               v
    // --------------------------------------------------
    // ||    |    |    ||    |    |    ||    |    |    ||
    // || 12 | 78 | 21 || 55 | 18 | 78 || 92 | 41 | 18 ||
    // ||    |    |    ||    |    |    ||    |    |    ||
    // --------------------------------------------------
    // ^     ^    ^    ^     ^    ^    ^     ^    ^    ^
    // |     |    |    |     |    |    |     |    |    |
    // pi  pi+1 pi+2 pi+3  pi+4 pi+5 pi+6  pi+7 pi+8 pi+9
    for (int i = 0; i < DIM*DIM ; ++i) {
        for (int j = 0; j < DIM*DIM -i; ++j) {
            // boubleSort (desloca o maior elemento para o final do vetor)
            if(pi[j] > pi[j+1]){
                //subistituição sem usar variavel auxiliar em C XD
                pi[j]   ^=pi[j+1];
                pi[j+1] ^=pi[j];
                pi[j]   ^=pi[j+1];
            }
        }
    }
}

int main() {
    int matrix[DIM][DIM];
    fillMatrix(matrix);
    printMatrix(matrix);
    sortMatrix(matrix);
    printMatrix(matrix);
}