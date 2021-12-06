#pragma once
#include <stdio.h>
#define CLUSTER_SIZE 8192

unsigned char* Encrypt(unsigned char* cluster)
{
	unsigned char* res = (unsigned char*)malloc(CLUSTER_SIZE * sizeof(unsigned char*));
	for (int i = 0; i < CLUSTER_SIZE; i++)
		res[CLUSTER_SIZE - 1 - i] = cluster[i] + 5;
	return res;
}

unsigned char* Decrypt(unsigned char* cluster)
{
	unsigned char* res = (unsigned char*)malloc(CLUSTER_SIZE * sizeof(unsigned char*));
	for (int i = 0; i < CLUSTER_SIZE; i++)
		res[i] = cluster[CLUSTER_SIZE - 1 - i] - 5;
	return res;
}