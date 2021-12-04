#define _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_DEPRECATE
#define _CRT_NONSTDC_NO_DEPRECATE
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>
#include <math.h>
#include <time.h>
#include <Windows.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cwchar>
#include <vector>
#include "datetime.h"
#include "conv.h"
#include "string_s.h"
#include "AES.h"
#define OFFSET_CLUS 4
#define RETRY_SIZE 64
#define MAX 100
#define BIG_MAX 1000
#define CLUS_FAT 128
#define BLOCK_SIZE 512
#define TOTAL_SIZE 4294967296
using namespace std;

// Declaration of functions
bool ReadBlock(int numBlock, unsigned char* buf);
bool WriteBlock(int numBlock, unsigned char* buf);
bool ReadBlock(int numBlock, const wchar_t* dwFile, unsigned char* buf);
bool WriteBlock(int numBlock, const wchar_t* dwFile, unsigned char* buf);
char* ReadOffset(unsigned char* block, const char* offset, int numBytes);
void WriteOffset(unsigned char* block, const char* offset, const char* description);
unsigned char* WriteFat(int cluster, const char* description);
char* ReadFat(int cluster);
int IndexCluster(int cluster);
int IndexBlock(int block);
bool SetPrivilege();
bool InitializeVolume();
void Print(unsigned char* block);
bool CreateVolume();
bool FormatVolume();
bool SetPasswordVolume(const char* password);
bool CheckPasswordVolume(const char* password);
bool ChangePasswordVolume(const char* password);
bool RemovePasswordVolume();
void ListFile();
bool SetPasswordFile(const char* password, const char* file);
bool CheckPasswordFile(const char* password, const char* file);
bool ChangePasswordFile(const char* password, const char* file);
bool RemovePasswordFile(const char* file);
bool ImportFile(const char* file);
bool OutportFile(const char* file);
bool DeletedFile(const char* file);

// Declaration of variables
const wchar_t* dwFileName = L"MyFS.DAT";
const char* fileName = "MyFS.DAT";
const char* nameVolume = "MyFS";
int byteBlock = 512;
int blockClus = 16;
int blockBoot = 32;
int numFat = 1;
const char* typeVolume = "DAT";
int blockVol = 8388608;
int blockFat = 4096;
int beginClus = 2;
int copyBoot = 16;
int blockSystem = 4128;
int blockData = 8384480;
int byteClus = 4;
int byteEntry = 64;
int numEntry = 0;

const char* FreeClus = "00000000";
const char* BadClus = "0ffffff7";
const char* EofClus = "0fffffff";
const char* SystemClus = "ffffffff";

// Read specific block on file
bool ReadBlock(int numBlock, unsigned char* buf)
{
	bool retCode = false;
	unsigned char block[BLOCK_SIZE];
	DWORD dwBytesRead = 0;
	HANDLE hFile = NULL;

	hFile = CreateFile(dwFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;
	else
	{
		SetFilePointer(hFile, numBlock * BLOCK_SIZE, NULL, FILE_BEGIN);
		if (!ReadFile(hFile, block, BLOCK_SIZE, &dwBytesRead, NULL))
			printf("Error in reading file\n");
		else
		{
			// Copy boot block into buffer and set retCode
			memcpy(buf, block, BLOCK_SIZE);
			retCode = true;
		}
		// Close the handle
		CloseHandle(hFile);
	}
	return retCode;
}

// Write specific block on file
bool WriteBlock(int numBlock, unsigned char* buf)
{
	bool retCode = false;
	unsigned char block[BLOCK_SIZE];
	DWORD dwBytesWrite = 0;
	HANDLE hFile = NULL;

	hFile = CreateFile(dwFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;
	else
	{
		SetFilePointer(hFile, numBlock * BLOCK_SIZE, NULL, FILE_BEGIN);
		if (!WriteFile(hFile, buf, BLOCK_SIZE, &dwBytesWrite, NULL))
			printf("Error in writing file\n");
		else
			retCode = true;
		// Close the handle
		CloseHandle(hFile);
	}
	return retCode;
}

// Read specific block on file
bool ReadBlock(int numBlock, const wchar_t* dwFile, unsigned char* buf)
{
	bool retCode = false;
	unsigned char block[BLOCK_SIZE];
	DWORD dwBytesRead = 0;
	HANDLE hFile = NULL;

	hFile = CreateFile(dwFile, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;
	else
	{
		SetFilePointer(hFile, numBlock * BLOCK_SIZE, NULL, FILE_BEGIN);
		if (!ReadFile(hFile, block, BLOCK_SIZE, &dwBytesRead, NULL))
			printf("Error in reading file\n");
		else
		{
			// Copy boot block into buffer and set retCode
			memcpy(buf, block, BLOCK_SIZE);
			retCode = true;
		}
		// Close the handle
		CloseHandle(hFile);
	}
	return retCode;
}

// Write specific block on file
bool WriteBlock(int numBlock, const wchar_t* dwFile, unsigned char* buf)
{
	bool retCode = false;
	unsigned char block[BLOCK_SIZE];
	DWORD dwBytesWrite = 0;
	HANDLE hFile = NULL;

	hFile = CreateFile(dwFile, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;
	else
	{
		SetFilePointer(hFile, numBlock * BLOCK_SIZE, NULL, FILE_BEGIN);
		if (!WriteFile(hFile, buf, BLOCK_SIZE, &dwBytesWrite, NULL))
			printf("Error in writing file\n");
		else
			retCode = true;
		// Close the handle
		CloseHandle(hFile);
	}
	return retCode;
}

// Read offset by block index
char* ReadOffset(unsigned char* block, const char* offset, int numBytes, bool reverse)
{
	unsigned char* buf = (unsigned char*)malloc(numBytes * sizeof(unsigned char*));
	if (reverse)
		for (int i = Hex2Dec(offset); i < Hex2Dec(offset) + numBytes; i++)
			buf[numBytes - 1 - (i - Hex2Dec(offset))] = block[i];
	else
		for (int i = Hex2Dec(offset); i < Hex2Dec(offset) + numBytes; i++)
			buf[i - Hex2Dec(offset)] = block[i];

	char res[MAX] = "";
	for (int i = 0; i < numBytes; i++)
	{
		char temp[100];
		sprintf(temp, "%02x", buf[i]);
		strcat(res, temp);
	}
	free(buf);
	return res;
}

// Write offset by block index
void WriteOffset(unsigned char* block, const char* offset, const char* description, bool reverse)
{
	int numBytes = (strlen(description) % 2 == 0) ? strlen(description) / 2 : strlen(description) / 2 + 1;
	unsigned char* buf = (unsigned char*)malloc(numBytes * sizeof(unsigned char*));
	if (strlen(description) % 2 == 0)
		for (int i = 0; i < numBytes; i++)
		{
			char temp[3];
			sprintf(temp, "%c%c", description[2 * i], description[2 * i + 1]);
			buf[i] = (unsigned char)Hex2Dec(temp);
		}
	else
		for (int i = 0; i < numBytes; i++)
		{
			char temp[3];
			if (i == 0) sprintf(temp, "0%c", description[i]);
			else sprintf(temp, "%c%c", description[2 * i - 1], description[2 * i]);
			buf[i] = (unsigned char)Hex2Dec(temp);
		}
	if (reverse)
		for (int i = Hex2Dec(offset); i < Hex2Dec(offset) + numBytes; i++)
			block[i] = buf[numBytes - 1 - (i - Hex2Dec(offset))];
	else
		for (int i = Hex2Dec(offset); i < Hex2Dec(offset) + numBytes; i++)
			block[i] = buf[i - Hex2Dec(offset)];
	free(buf);
}

// Read cluster in FAT table
char* ReadFat(int cluster)
{
	unsigned char* block = (unsigned char*)malloc(BLOCK_SIZE * sizeof(unsigned char*));
	ReadBlock(cluster / (byteBlock / OFFSET_CLUS) + blockBoot, block);

	char* res = (char*)malloc(OFFSET_CLUS * 2 * sizeof(char*));
	res = ReadOffset(block, Dec2Hex(cluster % (byteBlock / OFFSET_CLUS) * OFFSET_CLUS), OFFSET_CLUS, true);
	return res;
}

// Write cluster by FAT table
unsigned char* WriteFat(int cluster, const char* description)
{
	unsigned char* block = (unsigned char*)malloc(BLOCK_SIZE * sizeof(unsigned char*));
	ReadBlock(cluster / (byteBlock / OFFSET_CLUS) + blockBoot, block);

	WriteOffset(block, Dec2Hex(cluster % (byteBlock / OFFSET_CLUS) * OFFSET_CLUS), description, true);
	return block;
}

// Index of cluster (= block)
int IndexCluster(int cluster)
{
	return blockSystem + (cluster - beginClus) * blockClus;
}

// Index of block (= cluster)
int IndexBlock(int block)
{
	return (block - blockSystem) / blockClus + beginClus;
}

// Print block
void Print(unsigned char* block)
{
	for (int i = 0; i < BLOCK_SIZE; i++)
	{
		printf("%02x ", block[i]);
		if (i % 16 == 15) printf("\n");
	}
}

// Set privilege for file
bool SetPrivilege()
{
	LUID luid;
	if (!LookupPrivilegeValue(0, SE_MANAGE_VOLUME_NAME, &luid))
		return false;

	HANDLE token;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
		return false;

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(token, 0, &tp, sizeof(TOKEN_PRIVILEGES), static_cast<PTOKEN_PRIVILEGES>(0), static_cast<PDWORD>(0)))
		return false;

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		return false;

	return true;
}

// Initialize volume (all offset = 00h)
bool InitializeVolume()
{
	bool retCode = true;
	bool granted = SetPrivilege();
	HANDLE hFile = NULL;

	hFile = CreateFile(dwFileName, GENERIC_WRITE, 0, 0, OPEN_ALWAYS, FILE_FLAG_NO_BUFFERING, 0);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;
	else
	{
		LARGE_INTEGER targetPointer;
		targetPointer.QuadPart = TOTAL_SIZE;
		SetFilePointerEx(hFile, targetPointer, 0, FILE_BEGIN);

		if (!SetEndOfFile(hFile))
			retCode = false;

		if (granted)
			if (!SetFileValidData(hFile, TOTAL_SIZE))
				retCode = false;
		// Close the handle
		CloseHandle(hFile);
	}
	return retCode;
}

// Create volume
bool CreateVolume()
{
	if (!InitializeVolume())
	{
		printf("Initialize volume failed!\n");
		return false;
	}

//	Date CurrentDate = _GetCurrentDate();
//	Time CurrentTime = _GetCurrentTime();
//	FILE* f = fopen("datetime.txt", "w");
//	fprintf(f, "%d-%d-%d %d:%d:%d", CurrentDate.day, CurrentDate.month, CurrentDate.year, CurrentTime.hour, CurrentTime.minute, CurrentTime.second);
//	fclose(f);

	return true;
}

// Format volume
bool FormatVolume()
{
	remove(fileName);
	if (!InitializeVolume())
	{
		printf("Initialize volume failed!\n");
		return false;
	}

	// BootBlock
	unsigned char* BootBlock = (unsigned char*)malloc(BLOCK_SIZE * sizeof(unsigned char*));
	ReadBlock(0, BootBlock);

//	char date[MAX];
//	char time[MAX];
//	FILE* f = fopen("datetime.txt", "r");
//	fscanf(f, "%s %s", date, time);
//	Date CurrentDate = ScanDate(date);
//	Time CurrentTime = ScanTime(time);
//	fclose(f);

	WriteOffset(BootBlock, "00", String2Hex(nameVolume), false);
	WriteOffset(BootBlock, "10", Dec2Hex(byteBlock), true);
	WriteOffset(BootBlock, "12", Dec2Hex(blockClus), true);
	WriteOffset(BootBlock, "13", Dec2Hex(blockBoot), true);
	WriteOffset(BootBlock, "15", Dec2Hex(numFat), true);
	WriteOffset(BootBlock, "16", String2Hex(typeVolume), false);
	WriteOffset(BootBlock, "1A", Dec2Hex(blockVol), true);
	WriteOffset(BootBlock, "1E", Dec2Hex(blockFat), true);
	WriteOffset(BootBlock, "20", Dec2Hex(beginClus), true);
	WriteOffset(BootBlock, "22", Dec2Hex(copyBoot), true);
	WriteOffset(BootBlock, "24", Date2Hex(GetCreatedDateFile(fileName)), true);
	WriteOffset(BootBlock, "26", Time2Hex(GetCreatedTimeFile(fileName)), true);
	WriteOffset(BootBlock, "28", Date2Hex(GetModifiedDateFile(fileName)), true);
	WriteOffset(BootBlock, "2A", Time2Hex(GetModifiedTimeFile(fileName)), true);
	WriteOffset(BootBlock, "2C", Date2Hex(GetAccessDateFile(fileName)), true);
	WriteOffset(BootBlock, "2E", Time2Hex(GetAccessTimeFile(fileName)), true);
	WriteOffset(BootBlock, "30", "0", true);
	WriteOffset(BootBlock, "31", Dec2Hex(blockSystem), true);
	WriteOffset(BootBlock, "35", Dec2Hex(blockData), true);
	WriteOffset(BootBlock, "3C", Dec2Hex(byteClus), true);
	WriteOffset(BootBlock, "3D", Dec2Hex(byteEntry), true);
	WriteOffset(BootBlock, "3E", Dec2Hex(numEntry), true);
	WriteOffset(BootBlock, "3F", "F", true);
	WriteOffset(BootBlock, "40", "0000000000000000000000000000000", true);
	WriteOffset(BootBlock, "1FE", "6969", true);

	WriteBlock(0, BootBlock);
	WriteBlock(copyBoot, BootBlock);
	free(BootBlock);

	// FAT table
	unsigned char* FatBlock = (unsigned char*)malloc(BLOCK_SIZE * sizeof(unsigned char*));
	ReadBlock(blockBoot, FatBlock);

	WriteOffset(FatBlock, "00", SystemClus, true);
	WriteOffset(FatBlock, "04", SystemClus, true);
	WriteOffset(FatBlock, "08", EofClus, true);

	WriteBlock(blockBoot, FatBlock);
	free(FatBlock);

	return true;
}

// Set password volume
bool SetPasswordVolume(const char* password)
{
	unsigned char* BootBlock = (unsigned char*)malloc(BLOCK_SIZE * sizeof(unsigned char*));
	ReadBlock(0, BootBlock);

	if (Hex2Dec(ReadOffset(BootBlock, "30", 1, true)) == 1)
		return false;

	if (Hex2Dec(ReadOffset(BootBlock, "30", 1, true)) == 0)
	{
		int PaddedLength = GetPaddedLength((unsigned char*)password);
		char* SecurityPassword = strsub(UHex2Hex(AesEncrypt((unsigned char*)password)), 0, PaddedLength * 2);
		WriteOffset(BootBlock, "30", "1", true);
		WriteOffset(BootBlock, "40", (const char*)SecurityPassword, true);
		WriteBlock(0, BootBlock);
	}

	free(BootBlock);
	return true;
}

// Check password volume
bool CheckPasswordVolume(const char* password)
{
	unsigned char* BootBlock = (unsigned char*)malloc(BLOCK_SIZE * sizeof(unsigned char*));
	ReadBlock(0, BootBlock);

	if (Hex2Dec(ReadOffset(BootBlock, "30", 1, true)) == 0)
	{
		printf("No password!\n");
		return false;
	}

	char* SecurityPassword = ReadOffset(BootBlock, "40", 16, true);
	char* Password = UHex2Hex(AesDecrypt(Hex2UHex(SecurityPassword)));
	int ret = strcmp(Hex2String(Password), password);
	free(BootBlock);
	
	if (ret != 0) return false;
	return true;
}

// Change password volume
bool ChangePasswordVolume(const char* password)
{
	unsigned char* BootBlock = (unsigned char*)malloc(BLOCK_SIZE * sizeof(unsigned char*));
	ReadBlock(0, BootBlock);

	if (Hex2Dec(ReadOffset(BootBlock, "30", 1, true)) == 0)
	{
		printf("No password!");
		return false;
	}

	if (CheckPasswordVolume(password))
		return false;

	WriteOffset(BootBlock, "40", "0000000000000000000000000000000", true);
	WriteBlock(0, BootBlock);

	int PaddedLength = GetPaddedLength((unsigned char*)password);
	char* SecurityPassword = strsub(UHex2Hex(AesEncrypt((unsigned char*)password)), 0, PaddedLength * 2);
	WriteOffset(BootBlock, "30", "1", true);
	WriteOffset(BootBlock, "40", (const char*)SecurityPassword, true);
	WriteBlock(0, BootBlock);

	free(BootBlock);
	return true;
}

// Remove password volume
bool RemovePasswordVolume()
{
	unsigned char* BootBlock = (unsigned char*)malloc(BLOCK_SIZE * sizeof(unsigned char*));
	ReadBlock(0, BootBlock);

	if (Hex2Dec(ReadOffset(BootBlock, "30", 1, true)) == 0)
	{
		printf("No password!");
		return false;
	}

	WriteOffset(BootBlock, "30", "0", true);
	WriteOffset(BootBlock, "40", "0000000000000000000000000000000", true);
	WriteBlock(0, BootBlock);

	free(BootBlock);
	return true;
}

// List of file (file tree)
void ListFile()
{
	printf("%s\n", fileName);

	bool retCode = false;
	bool checkMainEntry = false;
	int fatTab = beginClus;
	int blockEntry = blockSystem;
	int totalEntry = 0;
	char LongName[BIG_MAX];
	char SubName[10];
	while (1)
	{
		for (int indexBlock = blockEntry; indexBlock < blockEntry + blockClus; indexBlock++)
		{
			unsigned char* Entry = (unsigned char*)malloc(BLOCK_SIZE * sizeof(unsigned char*));
			ReadBlock(indexBlock, Entry);

			for (int offset = 0; offset < BLOCK_SIZE; offset += RETRY_SIZE)
			{
				if (Entry[offset] == 0x00) {
					retCode = true; break;
				}
				else if (Entry[offset] == 0xe5)
					continue;
				else
				{
					// Main entry
					if (Entry[offset + 35] == 0xff)
					{
						strcpy(LongName, Hex2String(ReadOffset(Entry, Dec2Hex(offset), 8, false)));
						strcpy(SubName, Hex2String(ReadOffset(Entry, Dec2Hex(offset + 8), 4, false)));
						totalEntry = Hex2Dec(ReadOffset(Entry, Dec2Hex(offset + 33), 2, true));
					}
					// Sub entry
					else
					{
						strcat(LongName, Hex2String(ReadOffset(Entry, Dec2Hex(offset + 1), 31, false)));
						totalEntry--;
					}

					if (totalEntry == 0) checkMainEntry = true;
					
					if (checkMainEntry)
					{
						char FullName[BIG_MAX];
						strcpy(FullName, LongName);
						strcat(FullName, ".");
						strcat(FullName, SubName);

						printf("%c %s\n", (char)192, FullName);

						strcpy(LongName, "");
						strcpy(SubName, "");
						totalEntry = 0;
						checkMainEntry = false;
					}
				}
			}

			free(Entry);
			if (retCode) break;
		}
		if (Hex2Dec(ReadFat(fatTab)) == Hex2Dec(EofClus)) break;
		else blockEntry = IndexCluster(Hex2Dec(ReadFat(fatTab)));
		fatTab = Hex2Dec(ReadFat(fatTab));
	}
}

// Set password file
bool SetPasswordFile(const char* password, const char* file)
{
	bool retCode = false;
	bool matchFile = false;
	int fatTab = beginClus;
	int blockEntry = blockSystem;
	while (1)
	{
		for (int indexBlock = blockEntry; indexBlock < blockEntry + blockClus; indexBlock++)
		{
			unsigned char* Entry = (unsigned char*)malloc(BLOCK_SIZE * sizeof(unsigned char*));
			ReadBlock(indexBlock, Entry);

			for (int offset = 0; offset < BLOCK_SIZE; offset += RETRY_SIZE)
			{
				if (Entry[offset] == 0x00) {
					retCode = true; break;
				}
				else
				{
					// Main entry
					if (Entry[offset + 35] == 0xff)
					{
						char* x1 = Hex2String(ReadOffset(Entry, Dec2Hex(offset), 8, false));
						char* x2;
						if (strlen(file) <= 8) x2 = strsub(file, 0, strrfind(file, '.'));
						else x2 = strsub(file, 0, 8);
						if (strcmp(x1, x2) == 0) matchFile = true;
					}

					if (matchFile)
					{
						if (Hex2Dec(ReadOffset(Entry, Dec2Hex(offset + 32), 1, true)) == 1)
							return false;

						if (Hex2Dec(ReadOffset(Entry, Dec2Hex(offset + 32), 1, true)) == 0)
						{
							int PaddedLength = GetPaddedLength((unsigned char*)password);
							char* SecurityPassword = strsub(UHex2Hex(AesEncrypt((unsigned char*)password)), 0, PaddedLength * 2);
							WriteOffset(Entry, Dec2Hex(offset + 32), "1", true);
							WriteOffset(Entry, Dec2Hex(offset + 48), (const char*)SecurityPassword, true);
							WriteBlock(indexBlock, Entry);
						}

						matchFile = false;
						return true;
						break;
					}
				}
			}

			free(Entry);
			if (retCode) break;
		}
		if (Hex2Dec(ReadFat(fatTab)) == Hex2Dec(EofClus)) break;
		else blockEntry = IndexCluster(Hex2Dec(ReadFat(fatTab)));
		fatTab = Hex2Dec(ReadFat(fatTab));
	}

	return false;
}

// Check password file
bool CheckPasswordFile(const char* password, const char* file)
{
	bool retCode = false;
	bool matchFile = false;
	int fatTab = beginClus;
	int blockEntry = blockSystem;
	while (1)
	{
		for (int indexBlock = blockEntry; indexBlock < blockEntry + blockClus; indexBlock++)
		{
			unsigned char* Entry = (unsigned char*)malloc(BLOCK_SIZE * sizeof(unsigned char*));
			ReadBlock(indexBlock, Entry);

			for (int offset = 0; offset < BLOCK_SIZE; offset += RETRY_SIZE)
			{
				if (Entry[offset] == 0x00) {
					retCode = true; break;
				}
				else
				{
					// Main entry
					if (Entry[offset + 35] == 0xff)
					{
						char* x1 = Hex2String(ReadOffset(Entry, Dec2Hex(offset), 8, false));
						char* x2;
						if (strlen(file) <= 8) x2 = strsub(file, 0, strrfind(file, '.'));
						else x2 = strsub(file, 0, 8);
						if (strcmp(x1, x2) == 0) matchFile = true;
					}

					if (matchFile)
					{
						if (Hex2Dec(ReadOffset(Entry, Dec2Hex(offset + 32), 1, true)) == 0)
						{
							printf("No password!\n");
							return false;
						}

						char* SecurityPassword = ReadOffset(Entry, Dec2Hex(offset + 48), 16, true);
						char* Password = UHex2Hex(AesDecrypt(Hex2UHex(SecurityPassword)));
						int ret = strcmp(Hex2String(Password), password);

						if (ret != 0) return false;
						else return true;

						break;
					}
				}
			}

			free(Entry);
			if (retCode) break;
		}
		if (Hex2Dec(ReadFat(fatTab)) == Hex2Dec(EofClus)) break;
		else blockEntry = IndexCluster(Hex2Dec(ReadFat(fatTab)));
		fatTab = Hex2Dec(ReadFat(fatTab));
	}

	return false;
}

// Change password file
bool ChangePasswordFile(const char* password, const char* file)
{
	bool retCode = false;
	bool matchFile = false;
	int fatTab = beginClus;
	int blockEntry = blockSystem;
	while (1)
	{
		for (int indexBlock = blockEntry; indexBlock < blockEntry + blockClus; indexBlock++)
		{
			unsigned char* Entry = (unsigned char*)malloc(BLOCK_SIZE * sizeof(unsigned char*));
			ReadBlock(indexBlock, Entry);

			for (int offset = 0; offset < BLOCK_SIZE; offset += RETRY_SIZE)
			{
				if (Entry[offset] == 0x00) {
					retCode = true; break;
				}
				else
				{
					// Main entry
					if (Entry[offset + 35] == 0xff)
					{
						char* x1 = Hex2String(ReadOffset(Entry, Dec2Hex(offset), 8, false));
						char* x2;
						if (strlen(file) <= 8) x2 = strsub(file, 0, strrfind(file, '.'));
						else x2 = strsub(file, 0, 8);
						if (strcmp(x1, x2) == 0) matchFile = true;
					}

					if (matchFile)
					{
						if (Hex2Dec(ReadOffset(Entry, Dec2Hex(offset + 32), 1, true)) == 0)
						{
							printf("No password!");
							return false;
						}

						if (CheckPasswordFile(password, file))
							return false;


						WriteOffset(Entry, Dec2Hex(offset + 48), "0000000000000000000000000000000", true);
						WriteBlock(indexBlock, Entry);

						int PaddedLength = GetPaddedLength((unsigned char*)password);
						char* SecurityPassword = strsub(UHex2Hex(AesEncrypt((unsigned char*)password)), 0, PaddedLength * 2);
						WriteOffset(Entry, Dec2Hex(offset + 32), "1", true);
						WriteOffset(Entry, Dec2Hex(offset + 48), (const char*)SecurityPassword, true);
						WriteBlock(indexBlock, Entry);

						matchFile = false;
						return true;
						break;
					}
				}
			}

			free(Entry);
			if (retCode) break;
		}
		if (Hex2Dec(ReadFat(fatTab)) == Hex2Dec(EofClus)) break;
		else blockEntry = IndexCluster(Hex2Dec(ReadFat(fatTab)));
		fatTab = Hex2Dec(ReadFat(fatTab));
	}

	return false;
}

// Remove password file
bool RemovePasswordFile(const char* file)
{
	bool retCode = false;
	bool matchFile = false;
	int fatTab = beginClus;
	int blockEntry = blockSystem;
	while (1)
	{
		for (int indexBlock = blockEntry; indexBlock < blockEntry + blockClus; indexBlock++)
		{
			unsigned char* Entry = (unsigned char*)malloc(BLOCK_SIZE * sizeof(unsigned char*));
			ReadBlock(indexBlock, Entry);

			for (int offset = 0; offset < BLOCK_SIZE; offset += RETRY_SIZE)
			{
				if (Entry[offset] == 0x00) {
					retCode = true; break;
				}
				else
				{
					// Main entry
					if (Entry[offset + 35] == 0xff)
					{
						char* x1 = Hex2String(ReadOffset(Entry, Dec2Hex(offset), 8, false));
						char* x2;
						if (strlen(file) <= 8) x2 = strsub(file, 0, strrfind(file, '.'));
						else x2 = strsub(file, 0, 8);
						if (strcmp(x1, x2) == 0) matchFile = true;
					}

					if (matchFile)
					{
						if (Hex2Dec(ReadOffset(Entry, Dec2Hex(offset + 32), 1, true)) == 0)
						{
							printf("No password!\n");
							return false;
						}

						WriteOffset(Entry, Dec2Hex(offset + 32), "0", true);
						WriteOffset(Entry, Dec2Hex(offset + 48), "0000000000000000000000000000000", true);
						WriteBlock(indexBlock, Entry);

						matchFile = false;
						break;
					}
				}
			}

			free(Entry);
			if (retCode) break;
		}
		if (Hex2Dec(ReadFat(fatTab)) == Hex2Dec(EofClus)) break;
		else blockEntry = IndexCluster(Hex2Dec(ReadFat(fatTab)));
		fatTab = Hex2Dec(ReadFat(fatTab));
	}

	return false;
}

// Import file
bool ImportFile(const char* file)
{
	// Main name and sub name
	char* MainName = strsub(file, 0, strrfind(file, '.'));
	char* PartName = MainName;
	char* SubName = strsub(file, strrfind(file, '.') + 1);

	// Count number of sub-entry to save long name
	int numSubEntry = 0;
	if (strlen(file) > 8) numSubEntry = (int)ceil((double)(strlen(file) - 8) / 31);
	
	// Size of file (= byte)
	FILE* f = fopen(file, "r");
	if (f == NULL) return false;
	fseek(f, 0L, SEEK_END);
	int sizeFile = ftell(f);
	int blockFile = (int)ceil((float)sizeFile / byteBlock);
	int clusterFile = (int)ceil((float)blockFile / blockClus);
	fclose(f);

	// Date and time of file
	Date CreatedDate = GetCreatedDateFile(file);
	Time CreatedTime = GetCreatedTimeFile(file);
	Date ModifiedDate = GetModifiedDateFile(file);
	Time ModifiedTime = GetModifiedTimeFile(file);
	Date AccessDate = GetAccessDateFile(file);
	Time AccessTime = GetAccessTimeFile(file);

	// FAT table
	std::vector<int> EmptyCluster;
	int cluster = beginClus;
	while (EmptyCluster.size() < clusterFile)
	{
		if (cluster >= blockFat)
			break;
		if (Hex2Dec(ReadFat(cluster)) == 0)
			EmptyCluster.push_back(cluster);
		cluster++;
	}

	// Write entry in RDET
	bool retCode = false;
	bool writeMainEntry = false;
	int fatTab = beginClus;
	int blockEntry = blockSystem;
	int totalEntry = 1;
	while (1)
	{
		for (int indexBlock = blockEntry; indexBlock < blockEntry + blockClus; indexBlock++)
		{
			unsigned char* Entry = (unsigned char*)malloc(BLOCK_SIZE * sizeof(unsigned char*));
			ReadBlock(indexBlock, Entry);

			for (int offset = 0; offset < BLOCK_SIZE; offset += RETRY_SIZE)
			{
				// Main entry
				if (Entry[offset] == 0x00 && writeMainEntry == false)
				{
					WriteOffset(Entry, Dec2Hex(offset), String2Hex(strsub(PartName, 0, 8)), false);
					WriteOffset(Entry, Dec2Hex(offset + 8), String2Hex(SubName), false);
					WriteOffset(Entry, Dec2Hex(offset + 12), Date2Hex(CreatedDate), true);
					WriteOffset(Entry, Dec2Hex(offset + 14), Time2Hex(CreatedTime), true);
					WriteOffset(Entry, Dec2Hex(offset + 16), Date2Hex(ModifiedDate), true);
					WriteOffset(Entry, Dec2Hex(offset + 18), Time2Hex(ModifiedTime), true);
					WriteOffset(Entry, Dec2Hex(offset + 20), Date2Hex(AccessDate), true);
					WriteOffset(Entry, Dec2Hex(offset + 22), Time2Hex(AccessTime), true);
					WriteOffset(Entry, Dec2Hex(offset + 24), Dec2Hex(EmptyCluster[totalEntry - 1]), true);
					WriteOffset(Entry, Dec2Hex(offset + 28), Dec2Hex(sizeFile), true);
					WriteOffset(Entry, Dec2Hex(offset + 32), "0", true);
					WriteOffset(Entry, Dec2Hex(offset + 33), Dec2Hex(numSubEntry), true);
					WriteOffset(Entry, Dec2Hex(offset + 35), "ff", true);
					WriteOffset(Entry, Dec2Hex(offset + 36), "00000000000000000000000", true);
					WriteOffset(Entry, Dec2Hex(offset + 48), "0000000000000000000000000000000", true);

					PartName = strsub((const char*)PartName, 8);
					writeMainEntry = true;
				}
				// Sub entry
				else if (Entry[offset] == 0x00 && writeMainEntry == true)
				{
					WriteOffset(Entry, Dec2Hex(offset), Dec2Hex(totalEntry), true);
					WriteOffset(Entry, Dec2Hex(offset + 1), String2Hex(strsub(PartName, 0, 31)), false);
					WriteOffset(Entry, Dec2Hex(offset + 32), "00000000000000000000000000000", true);
					if (totalEntry == numSubEntry) WriteOffset(Entry, Dec2Hex(offset + 62), "Of", true);
					else WriteOffset(Entry, Dec2Hex(offset + 62), "00", true);

					PartName = strsub((const char*)PartName, 31);
					totalEntry++;
				}
				else
					continue;

				if (totalEntry > numSubEntry) {
					retCode = true; break;
				}
			}
			WriteBlock(indexBlock, Entry);

			free(Entry);
			if (retCode) break;
		}

		if (retCode == false)
		{
			cluster = fatTab;
			while (1)
			{
				if (cluster >= blockFat)
					break;
				if (Hex2Dec(ReadFat(cluster)) == 0)
				{
					WriteBlock(fatTab / (byteBlock / OFFSET_CLUS) + blockBoot, WriteFat(fatTab, HexResize(Dec2Hex(cluster), 8)));
					WriteBlock(cluster / (byteBlock / OFFSET_CLUS) + blockBoot, WriteFat(cluster, EofClus));
					break;
				}
				cluster++;
			}

			EmptyCluster.clear();
			cluster = beginClus;
			while (EmptyCluster.size() < clusterFile)
			{
				if (cluster >= blockFat)
					break;
				if (Hex2Dec(ReadFat(cluster)) == 0)
					EmptyCluster.push_back(cluster);
				cluster++;
			}
		}

		if (Hex2Dec(ReadFat(fatTab)) == Hex2Dec(EofClus)) break;
		else blockEntry = IndexCluster(Hex2Dec(ReadFat(fatTab)));
		fatTab = Hex2Dec(ReadFat(fatTab));
	}

	// Write cluster in FAT table
	for (int i = 0; i < EmptyCluster.size(); i++)
	{
		if (i == EmptyCluster.size() - 1)
			WriteBlock(cluster / (byteBlock / OFFSET_CLUS) + blockBoot, WriteFat(EmptyCluster[i], EofClus));
		else
			WriteBlock(cluster / (byteBlock / OFFSET_CLUS) + blockBoot, WriteFat(EmptyCluster[i], Dec2Hex(EmptyCluster[i + 1])));
	}

	// Write description of file
	for (int indexBlock = 0; indexBlock < blockFile; indexBlock++)
	{
		unsigned char* Block = (unsigned char*)malloc(BLOCK_SIZE * sizeof(unsigned char*));
		wchar_t* dwFile = (wchar_t*)malloc((strlen(file) + 1) * sizeof(wchar_t*));
		mbstowcs(dwFile, file, strlen(file) + 1);
		ReadBlock(indexBlock, dwFile, Block);

		if ((indexBlock == blockFile - 1) && (sizeFile % byteBlock != 0))
			for (int offset = sizeFile % BLOCK_SIZE; offset < BLOCK_SIZE; offset++)
				Block[offset] = 0x00;
				

		WriteBlock((indexBlock % blockClus) + IndexCluster(EmptyCluster[indexBlock / blockClus]), Block);
		free(Block);
	}

	return true;
}

// Outport file
bool OutportFile(const char* file)
{
	bool retCode = false;
	bool matchFile = false;
	int fatTab = beginClus;
	int blockEntry = blockSystem;
	while (1)
	{
		for (int indexBlock = blockEntry; indexBlock < blockEntry + blockClus; indexBlock++)
		{
			unsigned char* Entry = (unsigned char*)malloc(BLOCK_SIZE * sizeof(unsigned char*));
			ReadBlock(indexBlock, Entry);

			for (int offset = 0; offset < BLOCK_SIZE; offset += RETRY_SIZE)
			{
				if (Entry[offset] == 0x00) {
					retCode = true; break;
				}
				else
				{
					// Main entry
					if (Entry[offset + 35] == 0xff)
					{
						char* x1 = Hex2String(ReadOffset(Entry, Dec2Hex(offset), 8, false));
						char* x2;
						if (strlen(file) <= 8) x2 = strsub(file, 0, strrfind(file, '.'));
						else x2 = strsub(file, 0, 8);
						if (strcmp(x1, x2) == 0) matchFile = true;
					}

					if (matchFile)
					{
						remove(file);

						int retrySize = Hex2Dec(ReadOffset(Entry, Dec2Hex(offset + 28), 4, true));
						int blockEntry = (int)ceil(retrySize / (float)byteBlock); 
						int startCluster = Hex2Dec(ReadOffset(Entry, Dec2Hex(offset + 24), 4, true));

						// Initialize file
						wchar_t* dwFile = (wchar_t*)malloc((strlen(file) + 1) * sizeof(wchar_t*));
						mbstowcs(dwFile, file, strlen(file) + 1);
						FILE* f = fopen(file, "w");
						fseek(f, retrySize, SEEK_SET);
						fputc('\0', f);
						fclose(f);
						
						int cluster = startCluster;
						int countBlock = 0;
						while (1)
						{
							int startBlock = IndexCluster(cluster);
							for (int block = startBlock; block < startBlock + blockClus; block++)
							{
								if (countBlock == blockEntry) break;
								unsigned char* BlockFile = (unsigned char*)malloc(BLOCK_SIZE * sizeof(unsigned char*));
								ReadBlock(block, BlockFile);
								WriteBlock(countBlock, dwFile, BlockFile);
								free(BlockFile);
								countBlock++;
							}
							cluster = Hex2Dec(ReadFat(cluster));
							if (cluster == Hex2Dec(EofClus)) break;
						}						

						matchFile = false;
						return true;
						break;
					}
				}
			}

			free(Entry);
			if (retCode) break;
		}
		if (Hex2Dec(ReadFat(fatTab)) == Hex2Dec(EofClus)) break;
		else blockEntry = IndexCluster(Hex2Dec(ReadFat(fatTab)));
		fatTab = Hex2Dec(ReadFat(fatTab));
	}

	return false;
}

// Delete file
bool DeletedFile(const char* file)
{
	int retrySize;
	int startCluster;

	// Initialize null block
	unsigned char* NullBlock = (unsigned char*)malloc(BLOCK_SIZE * sizeof(unsigned char*));
	for (int i = 0; i < BLOCK_SIZE; i++)
		NullBlock[i] = 0x00;

	bool retCode = false;
	bool matchFile = false;
	int fatTab = beginClus;
	int blockEntry = blockSystem;
	int totalEntry = 0;
	while (1)
	{
		for (int indexBlock = blockEntry; indexBlock < blockEntry + blockClus; indexBlock++)
		{
			unsigned char* Entry = (unsigned char*)malloc(BLOCK_SIZE * sizeof(unsigned char*));
			ReadBlock(indexBlock, Entry);

			for (int offset = 0; offset < BLOCK_SIZE; offset += RETRY_SIZE)
			{

				if (Entry[offset] == 0x00) {
					retCode = true; break;
				}
				else
				{
					// Main entry
					if (Entry[offset + 35] == 0xff)
					{
						char* x1 = Hex2String(ReadOffset(Entry, Dec2Hex(offset), 8, false));
						char* x2;
						if (strlen(file) <= 8) x2 = strsub(file, 0, strrfind(file, '.'));
						else x2 = strsub(file, 0, 8);
						if (strcmp(x1, x2) == 0) matchFile = true;
					}

					// Erase entry of file
					// Main entry
					if (Entry[offset + 35] == 0xff && matchFile == true)
					{
						retrySize = Hex2Dec(ReadOffset(Entry, Dec2Hex(offset + 28), 4, true));
						startCluster = Hex2Dec(ReadOffset(Entry, Dec2Hex(offset + 24), 4, true));
						totalEntry = Hex2Dec(ReadOffset(Entry, Dec2Hex(offset + 33), 2, true));
						WriteOffset(Entry, Dec2Hex(offset), "e5", true);
					}
					// Sub entry
					else if (matchFile == true)
					{
						WriteOffset(Entry, Dec2Hex(offset), "e5", true);
						totalEntry--;
					}
					else
						continue;

					if (totalEntry == 0)
					{
						// Erase description of file
						int cluster = startCluster;
						int countBlock = 0;
						while (1)
						{
							int startBlock = IndexCluster(cluster);
							for (int block = startBlock; block < startBlock + blockClus; block++)
							{
								if (countBlock == blockEntry) break;
								WriteBlock(block, NullBlock);
								countBlock++;
							}
							cluster = Hex2Dec(ReadFat(cluster));
							if (cluster == Hex2Dec(EofClus)) break;
						}
						
						// Erase FAT table of file
						std::vector<int> FileCluster;
						cluster = startCluster;
						while (1)
						{
							FileCluster.push_back(cluster);
							cluster = Hex2Dec(ReadFat(cluster));
							if (cluster == Hex2Dec(EofClus)) break;
						}
						free(NullBlock);

						for (int i = 0; i < FileCluster.size(); i++)
							WriteBlock(FileCluster[i] / (byteBlock / OFFSET_CLUS) + blockBoot, WriteFat(FileCluster[i], "00000000"));

						matchFile = false;
						break;
					}
				}
			}
			WriteBlock(indexBlock, Entry);

			free(Entry);
			if (!matchFile)
			{
				return true;
				break;
			}
			if (retCode) break;
		}
		if (Hex2Dec(ReadFat(fatTab)) == Hex2Dec(EofClus)) break;
		else blockEntry = IndexCluster(Hex2Dec(ReadFat(fatTab)));
		fatTab = Hex2Dec(ReadFat(fatTab));
	}

	return false;
}

// Main function
int main()
{
	bool havePasswordVolume = false;
	unsigned char* BootBlock = (unsigned char*)malloc(BLOCK_SIZE * sizeof(unsigned char*));
	ReadBlock(0, BootBlock);
	if (Hex2Dec(ReadOffset(BootBlock, "30", 1, true)) == 0) havePasswordVolume = false;
	else havePasswordVolume = true;
	free(BootBlock);

	while (1)
	{
		int option = 0;
		printf("=================================================================================\n");
		printf("\t\t0\tEXIT\n");
		printf("\t\t1\tCREATE VOLUME\n");
		printf("\t\t2\tFORMAT VOLUME\n");
		printf("\t\t3\tSET PASSWORD VOLUME\n");
		printf("\t\t4\tCHECK PASSWORD VOLUME\n");
		printf("\t\t5\tCHANGE PASSWORD VOLUME\n");
		printf("\t\t6\tREMOVE PASSWORD VOLUME\n");
		printf("\t\t7\tLIST FILE IN VOLUME\n");
		printf("\t\t8\tSET PASSWORD FILE\n");
		printf("\t\t9\tCHECK PASSWORD FILE\n");
		printf("\t\t10\tCHANGE PASSWORD FILE\n");
		printf("\t\t11\tREMOVE PASSWORD FILE\n");
		printf("\t\t12\tIMPORT FILE\n");
		printf("\t\t13\tOUTPORT FILE\n");
		printf("\t\t14\tDELETE FILE\n");
		printf("=================================================================================\n");
		printf("\t\tOPTION = ");
		scanf("%d", &option);

		if (option == 0) break;

		char password[16];
		char passwordFile[16];
		char cFile[MAX];

		FILE* file;
		if (file = fopen(fileName, "r"))
		{
			fclose(file);
			switch (option)
			{
				case 1:
					printf("Volume %s already existed!\n", fileName);
					break;
				case 2:
					if (!havePasswordVolume)
					{
						if (FormatVolume()) printf("Format volume %s successfully!\n", fileName);
						else printf("Format fail!\n");
					}
					else
					{
						printf("TYPE PASSWORD: ");
						scanf("%s", &password);
						if (CheckPasswordVolume(password))
						{
							printf("Password match!\n");
							if (FormatVolume())
							{
								havePasswordVolume = false;
								printf("Format volume %s successfully!\n", fileName);
							}
							else printf("Format fail!\n");
						}
						else printf("Password doesn't match!\n");
					}
					break;
				case 3:
					if (!havePasswordVolume)
					{
						printf("TYPE PASSWORD: ");
						scanf("%s", &password);
						if (SetPasswordVolume(password))
						{
							printf("Password is set successfully!\n");
							havePasswordVolume = true;
						}
						else printf("Password already existed!\n");
					}
					else printf("Cannot set password because password already existed!\n");
					break;
				case 4:
					printf("TYPE PASSWORD: ");
					scanf("%s", &password);
					if (CheckPasswordVolume(password)) printf("Password match!\n");
					else printf("Password doesn't match!\n");
					break;
				case 5:
					if (!havePasswordVolume) printf("Cannot change password because no password!\n");
					else
					{
						printf("TYPE OLD PASSWORD: ");
						scanf("%s", &password);
						if (CheckPasswordVolume(password))
						{
							printf("Password match!\n");
							printf("TYPE NEW PASSWORD: ");
							scanf("%s", &password);
							if (ChangePasswordVolume(password)) printf("Password is changed!\n");
							else printf("Password is the same\n");
						}
						else printf("Password doesn't match!\n");
					}
					break;
				case 6:
					if (!havePasswordVolume) printf("Cannot remove password because no password!\n");
					else
					{
						printf("TYPE PASSWORD: ");
						scanf("%s", &password);
						if (CheckPasswordVolume(password))
						{
							printf("Password match!\n");
							if (RemovePasswordVolume())
							{
								printf("Password is reset!\n");
								havePasswordVolume = true;
							}
							else printf("");
						}
						else printf("Password doesn't match!\n");
					}
					break;
				case 7:
					if (!havePasswordVolume) ListFile();
					else
					{
						printf("TYPE PASSWORD: ");
						scanf("%s", &password);
						if (CheckPasswordVolume(password))
						{
							printf("Password match!\n");
							ListFile();
						}
						else printf("Password doesn't match!\n");
					}
					break;
				case 8:
					if (!havePasswordVolume)
					{
						printf("NAME FILE: ");
						scanf("%s", &cFile);
						printf("TYPE PASSWORD: ");
						scanf("%s", &password);
						if (SetPasswordFile(password, cFile)) printf("Password is set successfully!\n");
						else printf("Password already existed!\n");
					}
					else
					{
						printf("TYPE PASSWORD: ");
						scanf("%s", &password);
						if (CheckPasswordVolume(password))
						{
							printf("Password match!\n");
							printf("NAME FILE: ");
							scanf("%s", &cFile);
							printf("TYPE PASSWORD FILE: ");
							scanf("%s", &passwordFile);
							if (SetPasswordFile(passwordFile, cFile)) printf("Password is set successfully!\n");
							else printf("Password already existed!\n");
						}
						else printf("Password doesn't match!\n");
					}
					break;
				case 9:
					if (!havePasswordVolume)
					{
						printf("NAME FILE: ");
						scanf("%s", &cFile);
						printf("TYPE PASSWORD: ");
						scanf("%s", &password);
						if (CheckPasswordFile(password, cFile)) printf("Password match!\n");
						else printf("Password doesn't match or volume doesn't have a password!\n");
					}
					else
					{
						printf("TYPE PASSWORD: ");
						scanf("%s", &password);
						if (CheckPasswordVolume(password))
						{
							printf("Password match!\n");
							printf("NAME FILE: ");
							scanf("%s", &cFile);
							printf("TYPE PASSWORD FILE: ");
							scanf("%s", &passwordFile);
							if (CheckPasswordFile(passwordFile, cFile)) printf("Password match!\n");
							else printf("Password doesn't match or volume doesn't have a password!\n");
						}
						else printf("Password doesn't match!\n");
					}
					break;
				case 10:
					if (!havePasswordVolume)
					{
						printf("NAME FILE: ");
						scanf("%s", &cFile);
						printf("TYPE OLD PASSWORD: ");
						scanf("%s", &password);
						if (CheckPasswordFile(password, cFile))
						{
							printf("TYPE NEW PASSWORD: ");
							scanf("%s", &password);
							if (ChangePasswordFile(password, cFile)) printf("Password is changed!\n");
							else printf("Password is the same\n");
						}
						else printf("Password doesn't match!\n");
					}
					else
					{
						printf("TYPE PASSWORD: ");
						scanf("%s", &password);
						if (CheckPasswordVolume(password))
						{
							printf("Password match!\n");
							printf("NAME FILE: ");
							scanf("%s", &cFile);
							printf("TYPE OLD PASSWORD FILE: ");
							scanf("%s", &passwordFile);
							if (CheckPasswordFile(passwordFile, cFile))
							{
								printf("TYPE NEW PASSWORD FILE: ");
								scanf("%s", &passwordFile);
								if (ChangePasswordFile(passwordFile, cFile)) printf("Password is changed!\n");
								else printf("Password is the same\n");
							}
							else printf("Password doesn't match!\n");
						}
						else printf("Password doesn't match!\n");
					}
					break;
				case 11:
					if (!havePasswordVolume)
					{
						printf("NAME FILE: ");
						scanf("%s", &cFile);
						printf("TYPE PASSWORD: ");
						scanf("%s", &password);
						if (CheckPasswordFile(password, cFile))
						{
							if (RemovePasswordFile(cFile)) printf("Password is reset!\n");
							else printf("\n");
						}
						else printf("Password doesn't match!\n");
					}
					else
					{
						printf("TYPE PASSWORD: ");
						scanf("%s", &password);
						if (CheckPasswordVolume(password))
						{
							printf("Password match!\n");
							printf("NAME FILE: ");
							scanf("%s", &cFile);
							printf("TYPE PASSWORD FILE: ");
							scanf("%s", &passwordFile);
							if (CheckPasswordFile(passwordFile, cFile))
							{
								if (RemovePasswordFile(cFile)) printf("Password is reset!\n");
								else printf("\n");
							}
							else printf("Password doesn't match!\n");
						}
						else printf("Password doesn't match!\n");
					}
					break;
				case 12:
					if (!havePasswordVolume)
					{
						printf("IMPORT FILE: ");
						scanf("%s", &cFile);
						if (ImportFile(cFile)) printf("Importing file successfully!\n");
						else printf("File is not existed!\n");
					}
					else
					{
						printf("TYPE PASSWORD: ");
						scanf("%s", &password);
						if (CheckPasswordVolume(password))
						{
							printf("Password match!\n");
							printf("IMPORT FILE: ");
							scanf("%s", &cFile);
							if (ImportFile(cFile)) printf("Importing file successfully!\n");
							else printf("File is not existed!\n");
						}
						else printf("Password doesn't match!\n");
					}
					break;
				case 13:
					if (!havePasswordVolume)
					{
						printf("OUTPORT FILE: ");
						scanf("%s", &cFile);
						if (OutportFile(cFile)) printf("Outporting file successfully!\n");
						else printf("File is not existed!\n");
					}
					else
					{
						printf("TYPE PASSWORD: ");
						scanf("%s", &password);
						if (CheckPasswordVolume(password))
						{
							printf("Password match!\n");
							printf("OUTPORT FILE: ");
							scanf("%s", &cFile);
							if (OutportFile(cFile)) printf("Outporting file successfully!\n");
							else printf("File is not existed!\n");
						}
						else printf("Password doesn't match!\n");
					}
					break;
				case 14:
					if (!havePasswordVolume)
					{
						printf("DELETED FILE: ");
						scanf("%s", &cFile);
						if (DeletedFile(cFile)) printf("Deleting file successfully\n");
						else printf("File is not existed!\n");
					}
					else
					{
						printf("TYPE PASSWORD: ");
						scanf("%s", &password);
						if (CheckPasswordVolume(password))
						{
							printf("Password match!\n");
							printf("DELETED FILE: ");
							scanf("%s", &cFile);
							if (DeletedFile(cFile)) printf("Deleting file successfully\n");
							else printf("File is not existed!\n");
						}
						else printf("Password doesn't match!\n");
					}
					break;
				default:
					break;
			}
		}
		else
		{
			switch (option)
			{
				case 1:
					if (CreateVolume()) printf("Create volume %s successfully!\n", fileName);
					break;
				case 2:
				case 3:
				case 4:
				case 5:
				case 6:
				case 7:
				case 8:
				case 9:
				case 10:
				case 11:
				case 12:
				case 13:
				case 14:
					printf("Cannot find volume %s!\n", fileName);
					break;
				default:
					break;
			}
		}

		system("pause");
		system("cls");
	}


	return 0;
}