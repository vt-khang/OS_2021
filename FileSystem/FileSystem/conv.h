#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "string_s.h"
#define MAX 100
#define BIG_MAX 1000

// Declaration of functions
int Hex2Dec(const char* hex);
char* Dec2Hex(int dec);
char* String2Hex(const char* ch);
char* Hex2String(const char* hex);
char* Dec2Bin(int dec);
int Bin2Dec(const char* bin);
char* Bin2Hex(const char* bin);
char* Hex2Bin(const char* hex);
char* BinResize(const char* bin, int size);
char* HexResize(const char* hex, int size);
char* UHex2Hex(unsigned char* hex);
unsigned char* Hex2UHex(char* hex);

// Convert hexadecimal to decimal
int Hex2Dec(const char* hex)
{
	int dec = 0, base = 1;
	int n = strlen(hex);
	for (int i = n--; i >= 0; i--)
	{
		if (hex[i] >= '0' && hex[i] <= '9') {
			dec += (hex[i] - 48) * base; base *= 16;
		}
		else if (hex[i] >= 'A' && hex[i] <= 'F') {
			dec += (hex[i] - 55) * base; base *= 16;
		}
		else if (hex[i] >= 'a' && hex[i] <= 'f') {
			dec += (hex[i] - 87) * base; base *= 16;
		}
	}
	return dec;
}

// Convert decimal to hexadecimal
char* Dec2Hex(int dec)
{
	char* hex = (char*)malloc(MAX * sizeof(char*));
	int i = 0, quot = dec;
	while (quot != 0)
	{
		int temp = quot % 16;
		if (temp < 10) hex[i] = (char)(48 + temp);
		else hex[i] = (char)(55 + temp);
		i++; quot /= 16;
	}
	hex[i] = '\0';
	return strrev(hex);
}

// Convert string to hexadecimal
char* String2Hex(const char* ch)
{
	char* hex = (char*)malloc(MAX * sizeof(char*));
	strcpy(hex, "");
	for (int i = 0; i < strlen(ch); i++)
		strcat(hex, (const char*)Dec2Hex((int)ch[i]));
	return hex;
}

// Convert hexadecimal to string
char* Hex2String(const char* hex)
{
	char* ch = (char*)malloc(BIG_MAX * sizeof(char*));
	strcpy(ch, "");
	for (int i = 0; i < strlen(hex); i += 2)
	{
		char temp[2];
		temp[0] = Hex2Dec(strsub(hex, i, 2));
		temp[1] = '\0';
		strcat(ch, (const char*)temp);
	}
	return ch;
}

// Convert decimal to binary
char* Dec2Bin(int dec)
{
	char bin[MAX];
	int i = 0;
	while (dec > 0)
	{
		bin[i] = (char)(dec % 2) + '0';
		dec /= 2;
		i++;
	}
	bin[i] = '\0';
	return strrev(bin);
}

// Convert binary to decimal
int Bin2Dec(const char* bin)
{
	int dec = 0, j = 0;
	for (int i = strlen(bin) - 1; i >= 0; i--)
	{
		dec += (int)(bin[i] - '0') * pow(2, j);
		j++;
	}
	return dec;
}

// Convert binary to hexadecimal
char* Bin2Hex(const char* bin)
{
	if (strlen(bin) % 8 != 0)
		bin = BinResize(bin, strlen(bin) / 8 * 8 + 8);
	char* hex = (char*)malloc(MAX * sizeof(char*));
	strcpy(hex, "");
	for (int i = 0; i < strlen(bin); i += 8)
	{
		char* temp = strsub(bin, i, 8);
		strcat(hex, (const char*)HexResize(Dec2Hex(Bin2Dec(temp)), 2));
	}
	return hex;
}

// Convert hexadecimal to binary
char* Hex2Bin(const char* hex)
{
	if (strlen(hex) % 2 != 0)
		hex = HexResize(hex, strlen(hex) + 1);
	char* bin = (char*)malloc(MAX * sizeof(char*));
	strcpy(bin, "");
	for (int i = 0; i < strlen(hex); i += 2)
	{
		char* temp = strsub(hex, i, 2);
		strcat(bin, (const char*)BinResize(Dec2Bin(Hex2Dec(temp)), 8));
	}
	return bin;
}

// Resize binary
char* BinResize(const char* bin, int size)
{
	if (size <= strlen(bin))
		return (char*)bin;
	else
	{
		char* res = (char*)malloc(size * sizeof(char*));
		for (int i = 0; i < size; i++)
		{
			if (i < size - strlen(bin)) res[i] = '0';
			else res[i] = bin[i - (size - strlen(bin))];
		}
		res[size] = '\0';
		return res;
	}
}

// Resize hexadecimal
char* HexResize(const char* hex, int size)
{
	if (size <= strlen(hex))
		return (char*)hex;
	else
	{
		char* res = (char*)malloc(size * sizeof(char*));
		for (int i = 0; i < size; i++)
		{
			if (i < size - strlen(hex)) res[i] = '0';
			else res[i] = hex[i - (size - strlen(hex))];
		}
		res[size] = '\0';
		return res;
	}
}

// Convert hexadecimal (unsigned char) to hexadecimal (char)
char* UHex2Hex(unsigned char* hex)
{
	int size = strlen((char*)hex);
	char* res = (char*)malloc(2 * size * sizeof(char*));
	strcpy(res, "");
	for (int i = 0; i < size; i++)
	{
		char temp[MAX];
		sprintf(temp, "%02x", hex[i]);
		strcat(res, temp);
	}
	return res;
}

// Convert hexadecimal (char) to hexadecimal (unsigned char)
unsigned char* Hex2UHex(char* hex)
{
	int size = strlen((const char*)hex);
	unsigned char* res = (unsigned char*)malloc((size / 2) * sizeof(unsigned char*));
	for (int i = 0; i < size; i += 2)
	{
		char temp[3];
		sprintf(temp, "%c%c", hex[i], hex[i + 1]);
		res[i / 2] = (unsigned char)Hex2Dec(temp);
	}
	return res;
}