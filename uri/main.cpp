#include <stdio.h>

float media(){
    float  n1, n2;
    scanf("%f", &n1);
    while (n1 > 10.0 || n1 < 0.0){
        printf("nota invalida\n");
        scanf("%f", &n1);

    }
    scanf("%f", &n2);
    while (n2 > 10 || n2 < 0){
        printf("nota invalida\n");
        scanf("%f", &n2);
    }
    return (n1+n2)/2;
}

int main(){
    int option = 1;
    while(option == 1){
        printf("media = %.2f\n", media());
        printf("novo calculo (1-sim 2-nao)\n");
        scanf("%d",&option);
        if (option == 2)break;
        while (option != 1){
            printf("novo calculo (1-sim 2-nao)\n");
            scanf("%d", &option);
            if (option == 2)break;
        }
    }
    return 0;
}

