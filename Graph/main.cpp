#include <iostream>

int main() {
    FILE *arq = fopen("teste.txt","r");
    int mat, cont=0;
    char nome[10];
    float n1, n2, n3;

    if (arq==NULL) {
        printf("Erro");
        return 0;
    }
    while (fscanf(arq,"%d %s %f %f %f",&mat, &nome, &n1, &n2, &n3)!= EOF || cont++< 50) {
        printf("mat %d\n",mat);
        printf("nome %s\n",nome);
        printf("n1 %f\n",n1);
        printf("n2 %f\n",n2);
        printf("n3 %f\n",n3);
        printf("media: %.2f",float((n1+n2+n3)/3));
    }
    fprintf(arq,"\n421 novonome 8.7 6.5 10");
    fclose(arq);
    return 0;
}