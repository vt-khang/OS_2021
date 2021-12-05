#pragma once
#include <stdio.h>
#include <string.h>

// Declaration of functions
int strfind(const char* str, char ch);
int strrfind(const char* str, char ch);
char* strsub(const char* str, int index, int length);
char* strsub(const char* str, int index);

// Get index of first character in string
int strfind(const char* str, char ch)
{
	int index = -1;
	for (int i = 0; i < strlen(str); i++)
		if (str[i] == ch)
		{
			index = i;
			break;
		}
	return index;
}

// Get index of last character in string
int strrfind(const char* str, char ch)
{
	int index = -1;
	for (int i = 0; i < strlen(str); i++)
		if (str[i] == ch)
			index = i;
	return index;
}

// Get substring in string
char* strsub(const char* str, int index, int length)
{
	char* sub = (char*)malloc((length + 1) * sizeof(char*));
	strncpy(sub, &str[index], length);
	sub[length] = '\0';
	return sub;
}

// Get substring in string
char* strsub(const char* str, int index)
{
	if (index > strlen(str)) index = strlen(str);
	char* sub = (char*)malloc((strlen(str) - index + 1) * sizeof(char*));
	strncpy(sub, &str[index], strlen(str) - index);
	sub[strlen(str) - index] = '\0';
	return sub;
}