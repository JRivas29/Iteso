/**
 * Cifrado_SHA256.h
 *
 * Autor: JOse Rivas
 */


#ifndef Cifrado_SHA256_H
#define Cifrado_SHA256_H

#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#define uchar unsigned char
#define uint unsigned int

/*
    LA estrutura para  alamacenar lso datos de la codificacion SHA256

    data:       La cadena de caracteres o bloque de datos a utilizar.
    datalen:    El tamaño de los caracteres.
    bitlen:     El numero de bits a procesar.
    State:      El estado de hash.
    SHAXX:      SHA256 o SHA224
*/
typedef struct {
	unsigned char data[64];
	unsigned int datalen;
	unsigned int bitlen[2];
	unsigned int state[8];
             int SHAXX;
} SHA256_CTX;

void SHA256_Transform(SHA256_CTX *ctx, uchar data[]);

/*Inicializa la configurracion inicial y elige entre SHA256 y SHA224*/
extern void SHA256_Init(SHA256_CTX *ctx, int SHA_XXX);

/*Actualiza la estrutura y  acomoda la cadena de caracteres dependiendo del  tamño del mensaje*/
extern void SHA256_Update(SHA256_CTX *ctx, uchar data[], uint len);

/*Es la ultima corrido a donde rellena el buffer de er neseario, agrega el rellenado a los ultimos 8 bloques y los cifra por ultimas vez
y al final*/
extern void SHA256_Final(SHA256_CTX *ctx, uchar hash[]);

/*Funcion Main del SHA256*/
extern char* SHA256(char* data, int SHA_XXX);

#endif //Cifrado_SHA256_H