#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Cifrado_SHA256.h"

/*****      Macros      *****/
//trata dos enteros sin signo a y b como un entero de 64 bits y le suma c	
#define DBL_INT_ADD(a,b,c) if (a > 0xffffffff - (c)) ++b; a += c;

//Rotacion hacia derecha donde a es la entrada y b los espacios
#define RotDer(a,b) ((a >> b) | (a << (32-b)))
//Desplazamiento por derecha
#define DezplazDer(a,n) ((a >> n))

//Funcion CH que realizara operaciones logicas tomando como datos de entrada las palabras E, F y G
#define CH(x,y,z) ((x & y) ^ (~x & z)) 
//Funcion CH que realizara operaciones logicas tomando como datos de entrada las palabras A, B y C
#define MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))

//Funcion de la sumatoria 0
#define EP0(x) (RotDer(x,2) ^ RotDer(x,13) ^ RotDer(x,22))
//Funcion de la sumatoria 1
#define EP1(x) (RotDer(x,6) ^ RotDer(x,11) ^ RotDer(x,25))

//*****		Operaciones de compresion		*****/
//Calculo de sigma 0
#define SIG0(x) (RotDer(x,7) ^ RotDer(x,18) ^ DezplazDer(x,3))  //rotacion de 7 (XOR)^ rotacion de 18 (XOR)^ dezplazamiento
//Calculo de sigma 1
#define SIG1(x) (RotDer(x,17) ^ RotDer(x,19) ^ DezplazDer(x,10))


uint Matriz_K[64] = { //Se compone de 64 palabras hexadecimales, Raiz cubica delos primeros 64 numeros primos
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

uint Matriz_H_SHA256[8] = { //raiz cuadrada de los primeros 32 numeros primos
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

uint Matriz_H_SHA224[8] = {
    0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939, 0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4
};

void SHA256_Transform(SHA256_CTX *ctx, uchar data[])   //Construcon de la variable o array que contiene palabras hexadecimales de 32 bits
{
	uint a, b, c, d, e, f, g, h, i, j, t1, t2, m[64]; //Grupo de palabas de a - h, i y j son contadores, matriz Wt

	for (i = 0, j = 0; i < 16; ++i, j += 4)				//Los primeros 16 registros donde se almacena el mensajede entrada de m[0-15]
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for (; i < 64; ++i)			//REllena los 48  registros faltantes
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16]; //sumas del Mod32

	//Se le asigna a las primeras 8 palabras su eesta incial
	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	//Ronda cryrografica por cada palabra hasta rellenar las 64
	for (i = 0; i < 64; ++i) {  
		t1 = h + EP1(e) + CH(e, f, g) + Matriz_K[i] + m[i]; //Temporal 1 sumas de mod32
		t2 = EP0(a) + MAJ(a, b, c);							//Temporal 2 sumas de mod32
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	//Formacion de nuvos Hash asingna 
	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

void SHA256_Init(SHA256_CTX *ctx, int SHA_XXX)   //Lena la estructura y se pasa el SHA a utilizar  224 = 0 y 256 = 1 
{                                               // Si se escoge otro por defecto reproducira SHA256

	ctx->datalen = 0;
	ctx->bitlen[0] = 0;
	ctx->bitlen[1] = 0;

   if(SHA_XXX == 0 || SHA_XXX == 1){
    /*Nothing to do*/
   }
   else{
    SHA_XXX = 1;
   }

   if( SHA_XXX == 1){
    for (int x = 0; x < 8; x++)
    {
        ctx->state[x] = Matriz_H_SHA256[x];
		ctx->SHAXX = SHA_XXX;
    }
    
   }
   else if (SHA_XXX == 0)
   {
    for (int x = 0; x < 8; x++)
    {
        ctx->state[x] = Matriz_H_SHA224[x];
		ctx->SHAXX = SHA_XXX;
    }
   }
   else{
    /*Nothing to do*/
   }
   
}

void SHA256_Update(SHA256_CTX *ctx, uchar data[], uint len)
{
	for (uint i = 0; i < len; ++i) {
		//Rellena los datos de la estructura con los datos de la cadena 
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) { //Parte la cadena
			SHA256_Transform(ctx, ctx->data);
			DBL_INT_ADD(ctx->bitlen[0], ctx->bitlen[1], 512);  
			ctx->datalen = 0;
		}
        else{
            /*Nothing to do*/
        }
	}

}

void SHA256_Final(SHA256_CTX *ctx, uchar hash[])
{
	uint i = ctx->datalen;

	if (ctx->datalen < 56) { 	//REllena los datos del bufer faltante
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {						
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		SHA256_Transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	DBL_INT_ADD(ctx->bitlen[0], ctx->bitlen[1], ctx->datalen * 8);	// Agrega al relleno la longitud total del mensaje en bits y transforma.
	ctx->data[63] = ctx->bitlen[0];
	ctx->data[62] = ctx->bitlen[0] >> 8;
	ctx->data[61] = ctx->bitlen[0] >> 16;
	ctx->data[60] = ctx->bitlen[0] >> 24;
	ctx->data[59] = ctx->bitlen[1];
	ctx->data[58] = ctx->bitlen[1] >> 8;
	ctx->data[57] = ctx->bitlen[1] >> 16;
	ctx->data[56] = ctx->bitlen[1] >> 24;
	SHA256_Transform(ctx, ctx->data);

	for (i = 0; i < 4; ++i) {  //se invierte todo los bytes de golpe
		hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		if(ctx->SHAXX == 1){
			hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
		}
		else{
			/*nothing to do*/
		}
	}
}

char* SHA256(char* data, char* hashStr, int SHA_XXX) { /*La candena de datos, el Hash concatenado, SHA256 = 1  o SHA224 = 0*/

	int DataLen = strlen(data);             //Obtiene el tamaño de la cadena
	SHA256_CTX ctx;                         //Inicializa la estructura
	unsigned char hash[32];                 //Crea la variable que almacena el HASH
	hashStr = malloc(65);             		//Crea la variable de retrorno
	strcpy(hashStr, "");                    //Se le aignaun espacio en blanco

	SHA256_Init(&ctx, SHA_XXX);
	SHA256_Update(&ctx, data, DataLen);
	SHA256_Final(&ctx, hash, SHA_XXX);

	char s[3];
	for (int i = 0; i < 32; i++) {
		sprintf(s, "%02x", hash[i]);		//impresion separada
		strcat(hashStr, s);                 //Se concatena los caracteres en Hexadecimal
	}

	return hashStr;
}