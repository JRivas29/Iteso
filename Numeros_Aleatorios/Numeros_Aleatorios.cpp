#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sodium.h"


using namespace std;

#define FactK_MAX_SIZE (26U)
#define InitMin ('a'-1)
#define InitMay ('A'-1)

int FactK;

uint32_t Number[10];

int Cifrado_Cesar( int Fact) {

	char frase[] = "hola soy test";
	char FraseCesar[sizeof(frase)];

	printf("\n La frase es: %s", frase);
	char a = 0;

    if (FactK < 26 && FactK > 0) {
        for (int x = 0; x < sizeof(frase); x++) {
            if (frase[x] == ' ') {

                FraseCesar[x] = frase[x];

            }
            else if (frase[x] >= 'a' && frase[x] <= 'z'){
                if (frase[x] + FactK >= 'z') {

                    if (frase[x] == 'z') {

                        FraseCesar[x] = InitMin + FactK;

                    }
                    else {
                        a = ((frase[x] + FactK) - 'z') + InitMin;
                        FraseCesar[x] = a;
                    }
                }
                else {

                    FraseCesar[x] = frase[x] + FactK;

                }

            }
            else{

                FraseCesar[x] = ' ';
            }

        }
        cout<<endl<<"La frase cesar es: "<< FraseCesar << endl;
    }
	else {
		/*Nothing to do*/
	}
	return 0;
}

int main(void) {
     /*
     * Se comprueba que la interface inicie correctamente retornando un internamente un 1
     * y  un -1 si fallo el inicio.
     */

    printf("Generacion de numeros aleatorios \r\n");

    if (sodium_init() == -1) {
        printf("\nFallo la inicializon de la libreria de libsodium \n");
    }
    else {
        printf("\n Se inicializo  correctamente la libreria  \n");
    }

    printf("\n Se inicia la generacion de 10 numeros random \\n");

    for (int x = 0; x < 10; x++) {
        Number[x] = randombytes_random();
    }

    for (int x = 0; x < 10; x++) {
        if (x == 0) {
            printf("\nLos numeros del primer vetor de 10: { %d, ", Number[x]);
        }
        else if (x == 5) {
            printf("\r\n");
        }
        else if (x == 9) {
            printf("%d } \r \n", Number[x]);
        }
        else {
            printf("%d, ", Number[x]);
        }
    }

    printf("Se probara la generacion de numero random con rango col el codigo cesar \n\n");
	FactK = randombytes_uniform(FactK_MAX_SIZE);
    printf("El factor K generado es: %d \n", FactK);
	Cifrado_Cesar(FactK);


    return 0;
}
