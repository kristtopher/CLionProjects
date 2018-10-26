#include <iostream>
#include <stddef.h>
#include <math.h>
#include <list>
#include <vector>

#define porcentagem 5 // no máximo X% de perturbação
#define limite_superior 10
#define iteracoes 300 // condição de parada por numero de iteraçoes
#define iteracoesBL 50
#define n 5 //numero de pertubarções
#define lim 0.0001

float perturbacao(float solucao);
float x2(float solucao);
float Busca_local(float solucao);
float Criterio_aceitacao(float S, float S2);
std::vector<float> memoria;

int main() {
    srand(time(NULL));
    float S0 = 0; //soluçao inicial aleatoria
    float S = 0, S1 = 0, S2 = 0, Sfim = 0;
    int i = 0;

    S0 = rand() % limite_superior + 0;
    if ((rand() % 100 + 0) > 50)
        S0 = S0 * (-1);         //S0 <- Gera_Solução_Inicial
    printf("S0 %f\n",S0);
    memoria.push_back(S0);
    S = Busca_local(S0);        //S <- Busca_Local(S0 )

    while((i < iteracoes) ){       //enquanto (Condição de parada não satisfeita)
        S1 = perturbacao(S);    //s1 <- perturbação(s', memória)
        S2 = Busca_local(S1);   //S2 <-  Busca_Local(s1)
        S = Criterio_aceitacao(S,S2);//S <- Critério_de_Aceitação(S,S2,memória)
        i++;
        if (abs(S) < lim) break;
    }//fim-enquanto
    printf("O melhor valor encontrado é %f\n",S);
    return 0;
}

float Busca_local(float solucao){ // Hill climb x²
    float S = solucao;
    float R = 0, W =0;
    int i = 0;
    while(i < iteracoesBL ){
        R = perturbacao(S);
        for(int j=0; j <= n; j++){
            W = perturbacao(S);
            if(abs(x2(W)) < abs(x2(R))){ // minimizar
                R = W;
            }
        }
        if(abs(x2(R)) < abs(x2(S))) {
            S = R;
        }
        if (abs(S) < lim) break;
        i++;
        //printf("iteraçoes %d melhor s %f busca local\n",i,S);
    }
    //printf("saindo busca local %f \n", S);
    //printf("\nMelhor solução %.2f, após %d iterações", S,i);
    memoria.push_back(S);
    return S;
}

float perturbacao(float solucao){
    float perturb = 0;
    float R;
    int cont = 0;
    if(abs(solucao) < lim) return solucao;
    //printf("Entra perturbaçao\n");
    l:
    if(cont > 100)
        return memoria[memoria.size()-1];
    cont++;
    srand(time(NULL));
    perturb = (rand() % porcentagem + 0);
    if (perturb == 0) perturb = 0.002;
    if ((rand() % 100 + 0) > 50) perturb = perturb * (-1);
    R = solucao - (solucao * (perturb / 100.0));
    for(std::size_t i=0;i<memoria.size();++i){
       // printf("pos mem %d  dado %f R %f \n",i,memoria[i],R);
        if (memoria[i] == R) goto l;
    }
    memoria.push_back(R);
    //printf("R perturbado-> %f\n\n\n",R);
    return R;
}
float x2(float solucao){
    return (float) pow(solucao, 2);
}

float Criterio_aceitacao(float S, float S2) {
    if (abs(S2) < abs(S)) {
        S = S2;
        memoria.push_back(S);
    }
}