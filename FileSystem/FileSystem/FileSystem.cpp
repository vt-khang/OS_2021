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
#include "simple.h"
#define OFFSET_CLUS 4
#define RETRY_SIZE 64
#define MAX 100
#define BIG_MAX 1000
#define CLUS_FAT 128
#define BLOCK_SIZE 512
#define CLUSTER_SIZE 8192
#define TOTAL_SIZE 4294967296
using namespace std;

// Declaration of functions
bool ReadBlock(int numBlock, unsigned char* buf);
bool WriteBlock(int numBlock, unsigned char* buf);
bool ReadBlock(int numBlock, const wchar_t* dwFile, unsigned char* buf);
bool WriteBlock(int numBlock, const wchar_t* dwFile, unsigned char* buf);
bool ReadCluster(int numCluster, unsigned char* buf);
bool WriteCluster(int numCluster, unsigned char* buf);
bool ReadCluster(int numCluster, const wchar_t* dwFile, unsigned char* buf);
bool WriteCluster(int numCluster, const wchar_t* dwFile, unsigned char* buf);
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
bool ExistPasswordVolume();
bool SetPasswordVolume(const char* password);
bool CheckPasswordVolume(const char* password);
bool ChangePasswordVolume(const char* password);
bool RemovePasswordVolume();
void ListFile();
bool ExistPasswordFile(const char* file);
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

// Read specific cluster on file
bool ReadCluster(int numCluster, unsigned char* buf)
{
	bool retCode = false;
	unsigned char cluster[CLUSTER_SIZE];
	DWORD dwBytesRead = 0;
	HANDLE hFile = NULL;

	hFile = CreateFile(dwFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;
	else
	{
		SetFilePointer(hFile, IndexCluster(numCluster) * BLOCK_SIZE, NULL, FILE_BEGIN);
		if (!ReadFile(hFile, cluster, CLUSTER_SIZE, &dwBytesRead, NULL))
			printf("Error in reading file\n");
		else
		{
			// Copy boot block into buffer and set retCode
			memcpy(buf, cluster, CLUSTER_SIZE);
			retCode = true;
		}
		// Close the handle
		CloseHandle(hFile);
	}
	return retCode;
}

// Write specific cluster on file
bool WriteCluster(int numCluster, unsigned char* buf)
{
	bool retCode = false;
	unsigned char cluster[CLUSTER_SIZE];
	DWORD dwBytesWrite = 0;
	HANDLE hFile = NULL;

	hFile = CreateFile(dwFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;
	else
	{
		SetFilePointer(hFile, IndexCluster(numCluster) * BLOCK_SIZE, NULL, FILE_BEGIN);
		if (!WriteFile(hFile, buf, CLUSTER_SIZE, &dwBytesWrite, NULL))
			printf("Error in writing file\n");
		else
			retCode = true;
		// Close the handle
		CloseHandle(hFile);
	}
	return retCode;
}

// Read specific cluster on file
bool ReadCluster(int numCluster, const wchar_t* dwFile, unsigned char* buf)
{
	bool retCode = false;
	unsigned char cluster[CLUSTER_SIZE];
	DWORD dwBytesRead = 0;
	HANDLE hFile = NULL;

	hFile = CreateFile(dwFile, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;
	else
	{
		SetFilePointer(hFile, numCluster * CLUSTER_SIZE, NULL, FILE_BEGIN);
		if (!ReadFile(hFile, cluster, CLUSTER_SIZE, &dwBytesRead, NULL))
			printf("Error in reading file\n");
		else
		{
			// Copy boot block into buffer and set retCode
			memcpy(buf, cluster, CLUSTER_SIZE);
			retCode = true;
		}
		// Close the handle
		CloseHandle(hFile);
	}
	return retCode;
}

// Write specific cluster on file
bool WriteCluster(int numCluster, const wchar_t* dwFile, unsigned char* buf)
{
	bool retCode = false;
	unsigned char cluster[CLUSTER_SIZE];
	DWORD dwBytesWrite = 0;
	HANDLE hFile = NULL;

	hFile = CreateFile(dwFile, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;
	else
	{
		SetFilePointer(hFile, numCluster * CLUSTER_SIZE, NULL, FILE_BEGIN);
		if (!WriteFile(hFile, buf, CLUSTER_SIZE, &dwBytesWrite, NULL))
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

	WriteOffset(BootBlock, "00", String2Hex(nameVolume), false);					// Name of volume (short name)
	WriteOffset(BootBlock, "10", Dec2Hex(byteBlock), true);							// Byte of block = 512 byte
	WriteOffset(BootBlock, "12", Dec2Hex(blockClus), true);							// Block per cluster = 16 block
	WriteOffset(BootBlock, "13", Dec2Hex(blockBoot), true);							// Block of BootBlock = 32 block
	WriteOffset(BootBlock, "15", Dec2Hex(numFat), true);							// Number of FAT table = 1
	WriteOffset(BootBlock, "16", String2Hex(typeVolume), false);					// Type of volume (DAT)
	WriteOffset(BootBlock, "1A", Dec2Hex(blockVol), true);							// Size of volume = 8388608 block
	WriteOffset(BootBlock, "1E", Dec2Hex(blockFat), true);							// Size of FAT table = 4096 block
	WriteOffset(BootBlock, "20", Dec2Hex(beginClus), true);							// Cluster start of RDET = 2
	WriteOffset(BootBlock, "22", Dec2Hex(copyBoot), true);							// Copy of BootBlock = 16
	WriteOffset(BootBlock, "24", Date2Hex(GetCreatedDateFile(fileName)), true);		// Created date
	WriteOffset(BootBlock, "26", Time2Hex(GetCreatedTimeFile(fileName)), true);		// Created time
	WriteOffset(BootBlock, "28", Date2Hex(GetModifiedDateFile(fileName)), true);	// Modified date
	WriteOffset(BootBlock, "2A", Time2Hex(GetModifiedTimeFile(fileName)), true);	// Modified time
	WriteOffset(BootBlock, "2C", Date2Hex(GetAccessDateFile(fileName)), true);		// Access date
	WriteOffset(BootBlock, "2E", Time2Hex(GetAccessTimeFile(fileName)), true);		// Access time
	WriteOffset(BootBlock, "30", "0", true);										// Security status (1: password, 0: no password)
	WriteOffset(BootBlock, "31", Dec2Hex(blockSystem), true);						// Block of System = 4128
	WriteOffset(BootBlock, "35", Dec2Hex(blockData), true);							// Block of Data = 8384480
	WriteOffset(BootBlock, "3C", Dec2Hex(byteClus), true);							// Byte of cluster in FAT table = 4
	WriteOffset(BootBlock, "3D", Dec2Hex(byteEntry), true);							// Byte of entry in RDET = 64
	WriteOffset(BootBlock, "3E", Dec2Hex(numEntry), true);							// Number of entry (default = 0)
	WriteOffset(BootBlock, "3F", "F", true);										// Identification symbol of volume = F
	WriteOffset(BootBlock, "40", "0000000000000000000000000000000", true);			// Password volume (default = 0)
	WriteOffset(BootBlock, "1FE", "6969", true);									// Identification symbol of end of volume = 6969h

	WriteBlock(0, BootBlock);
	WriteBlock(copyBoot, BootBlock);
	free(BootBlock);

	// FAT table
	unsigned char* FatBlock = (unsigned char*)malloc(BLOCK_SIZE * sizeof(unsigned char*));
	ReadBlock(blockBoot, FatBlock);

	WriteOffset(FatBlock, "00", SystemClus, true);									// Cluster 0 (= System Cluster)
	WriteOffset(FatBlock, "04", SystemClus, true);									// Cluster 1 (= System Cluster)
	WriteOffset(FatBlock, "08", EofClus, true);										// Cluster 2 (= Start Cluster = Eof Cluster)

	WriteBlock(blockBoot, FatBlock);
	free(FatBlock);

	return true;
}

// Exist password volume
bool ExistPasswordVolume()
{
	unsigned char* BootBlock = (unsigned char*)malloc(BLOCK_SIZE * sizeof(unsigned char*));
	ReadBlock(0, BootBlock);

	if (Hex2Dec(ReadOffset(BootBlock, "30", 1, true)) == 0)
		return false;

	free(BootBlock);
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
		char* SecurityPassword = strsub(UHex2Hex(Aes_Encrypt((unsigned char*)password, (unsigned char*)password)), 0, PaddedLength * 2);
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
	char* Password = UHex2Hex(Aes_Decrypt(Hex2UHex(SecurityPassword), (unsigned char*)password));
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
	char* SecurityPassword = strsub(UHex2Hex(Aes_Encrypt((unsigned char*)password, (unsigned char*)password)), 0, PaddedLength * 2);
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
	printf("\n\n");
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

// Exist password file
bool ExistPasswordFile(const char* file)
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
							return false;
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
							char* SecurityPassword = strsub(UHex2Hex(Aes_Encrypt((unsigned char*)password, (unsigned char*)password)), 0, PaddedLength * 2);
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
						char* Password = UHex2Hex(Aes_Decrypt(Hex2UHex(SecurityPassword), (unsigned char*)password));
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
						char* SecurityPassword = strsub(UHex2Hex(Aes_Encrypt((unsigned char*)password, (unsigned char*)password)), 0, PaddedLength * 2);
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
	if (strfind(file, '.') == -1)
		return false;
	char* MainName = strsub(file, 0, strrfind(file, '.'));
	char* PartName = MainName;
	char* SubName = strsub(file, strrfind(file, '.') + 1);

	// Count number of sub-entry to save long name
	int numSubEntry = 0;
	if (strlen(MainName) > 8) numSubEntry = (int)ceil((float)(strlen(MainName) - 8) / (float)31);
	
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
		if (cluster >= blockFat * (byteBlock / OFFSET_CLUS))
			break;
		if (Hex2Dec(ReadFat(cluster)) == 0)
			EmptyCluster.push_back(cluster);
		else
			EmptyCluster.clear();
		cluster++;
	}
	if (EmptyCluster.size() == 0)
	{
		printf("Overloading cluster!\n");
		return false;
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
				if (cluster >= blockFat * (byteBlock / OFFSET_CLUS))
					break;
				if (Hex2Dec(ReadFat(cluster)) == 0)
					EmptyCluster.push_back(cluster);
				else
					EmptyCluster.clear();
				cluster++;
			}
			if (EmptyCluster.size() == 0)
			{
				printf("Overloading cluster!\n");
				return false;
			}
		}

		if (Hex2Dec(ReadFat(fatTab)) == Hex2Dec(EofClus)) break;
		else blockEntry = IndexCluster(Hex2Dec(ReadFat(fatTab)));
		fatTab = Hex2Dec(ReadFat(fatTab));
	}

	// Write cluster in FAT table
	int j = 0;
	for (int i = EmptyCluster[0] / (byteBlock / OFFSET_CLUS) + blockBoot; i <= EmptyCluster[EmptyCluster.size() - 1] / (byteBlock / OFFSET_CLUS) + blockBoot; i++)
	{
		unsigned char* block = (unsigned char*)malloc(BLOCK_SIZE * sizeof(unsigned char*));
		ReadBlock(i, block);

		while ((int)(EmptyCluster[j] / (byteBlock / OFFSET_CLUS) + blockBoot) == i)
		{
			if (j == EmptyCluster.size() - 1)
			{
				WriteOffset(block, Dec2Hex(EmptyCluster[j] % (byteBlock / OFFSET_CLUS) * OFFSET_CLUS), EofClus, true);
				break;
			}
			else WriteOffset(block, Dec2Hex(EmptyCluster[j] % (byteBlock / OFFSET_CLUS) * OFFSET_CLUS), Dec2Hex(EmptyCluster[j + 1]), true);
			j++;
		}

		WriteBlock(i, block);
		free(block);
	}

	// Write description of file
	for (int indexCluster = 0; indexCluster < clusterFile; indexCluster++)
	{
		unsigned char* Cluster = (unsigned char*)malloc(CLUSTER_SIZE * sizeof(unsigned char*));
		wchar_t* dwFile = (wchar_t*)malloc((strlen(file) + 1) * sizeof(wchar_t*));
		mbstowcs(dwFile, file, strlen(file) + 1);
		ReadCluster(indexCluster, dwFile, Cluster);

		if ((indexCluster == clusterFile - 1) && (sizeFile % CLUSTER_SIZE != 0))
			for (int offset = sizeFile % CLUSTER_SIZE; offset < CLUSTER_SIZE; offset++)
				Cluster[offset] = 0x00;

		WriteCluster(EmptyCluster[indexCluster], Encrypt(Cluster));
		free(Cluster);
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
						int blockEntry = (int)ceil((float)retrySize / byteBlock);
						int clusterEntry = (int)ceil((float)blockEntry / blockClus);
						int startCluster = Hex2Dec(ReadOffset(Entry, Dec2Hex(offset + 24), 4, true));

						// Initialize file
						wchar_t* dwFile = (wchar_t*)malloc((strlen(file) + 1) * sizeof(wchar_t*));
						mbstowcs(dwFile, file, strlen(file) + 1);
						FILE* f = fopen(file, "w");
						fseek(f, retrySize, SEEK_SET);
						fputc('\0', f);
						fclose(f);
						
						int cluster = startCluster;
						while (1)
						{
							unsigned char* ClusterFile = (unsigned char*)malloc(CLUSTER_SIZE * sizeof(unsigned char*));
							ReadCluster(cluster, ClusterFile);
							WriteCluster(cluster - startCluster, dwFile, Decrypt(ClusterFile));
							free(ClusterFile);
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
	unsigned char* NullCluster = (unsigned char*)malloc(CLUSTER_SIZE * sizeof(unsigned char*));
	for (int i = 0; i < CLUSTER_SIZE; i++)
		NullCluster[i] = 0x00;

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
						while (1)
						{
							WriteCluster(cluster, NullCluster);
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
						free(NullCluster);

						int j = 0;
						for (int i = FileCluster[0] / (byteBlock / OFFSET_CLUS) + blockBoot; i <= FileCluster[FileCluster.size() - 1] / (byteBlock / OFFSET_CLUS) + blockBoot; i++)
						{
							unsigned char* block = (unsigned char*)malloc(BLOCK_SIZE * sizeof(unsigned char*));
							ReadBlock(i, block);

							while ((int)(FileCluster[j] / (byteBlock / OFFSET_CLUS) + blockBoot) == i)
							{
								WriteOffset(block, Dec2Hex(FileCluster[j] % (byteBlock / OFFSET_CLUS) * OFFSET_CLUS), FreeClus, true);
								if (j == FileCluster.size() - 1) break; 
								j++;
							}

							WriteBlock(i, block);
							free(block);
						}

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
			havePasswordVolume = ExistPasswordVolume();
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
						while (1)
						{
							printf("TYPE PASSWORD: ");
							scanf("%s", &password);
							if (strlen(password) > 16) printf("Password is too long!\n");
							else break;
						}
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
						while (1)
						{
							printf("TYPE PASSWORD: ");
							scanf("%s", &password);
							if (strlen(password) > 16) printf("Password is too long!\n");
							else break;
						}
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
					if (!havePasswordVolume) printf("Cannot check password because no password!\n");
					else
					{
						while (1)
						{
							printf("TYPE PASSWORD: ");
							scanf("%s", &password);
							if (strlen(password) > 16) printf("Password is too long!\n");
							else break;
						}
						if (CheckPasswordVolume(password)) printf("Password match!\n");
						else printf("Password doesn't match!\n");
					}
					break;
				case 5:
					if (!havePasswordVolume) printf("Cannot change password because no password!\n");
					else
					{
						while (1)
						{
							printf("TYPE OLD PASSWORD: ");
							scanf("%s", &password);
							if (strlen(password) > 16) printf("Password is too long!\n");
							else break;
						}
						if (CheckPasswordVolume(password))
						{
							printf("Password match!\n");
							while (1)
							{
								printf("TYPE NEW PASSWORD: ");
								scanf("%s", &password);
								if (strlen(password) > 16) printf("Password is too long!\n");
								else break;
							}
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
						while (1)
						{
							printf("TYPE PASSWORD: ");
							scanf("%s", &password);
							if (strlen(password) > 16) printf("Password is too long!\n");
							else break;
						}
						if (CheckPasswordVolume(password))
						{
							printf("Password match!\n");
							if (RemovePasswordVolume())
							{
								printf("Password is reset!\n");
								havePasswordVolume = false;
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
						while (1)
						{
							printf("TYPE PASSWORD: ");
							scanf("%s", &password);
							if (strlen(password) > 16) printf("Password is too long!\n");
							else break;
						}
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
						if (!ExistPasswordFile(cFile))
						{
							while (1)
							{
								printf("TYPE PASSWORD FILE: ");
								scanf("%s", &passwordFile);
								if (strlen(passwordFile) > 16) printf("Password is too long!\n");
								else break;
							}
							if (SetPasswordFile(passwordFile, cFile)) printf("Password file %s is set successfully!\n", cFile);
							else printf("Password file already existed!\n");
						}
						else printf("Cannot set password file because password file already existed!\n");
					}
					else
					{
						while (1)
						{
							printf("TYPE PASSWORD: ");
							scanf("%s", &password);
							if (strlen(password) > 16) printf("Password is too long!\n");
							else break;
						}
						if (CheckPasswordVolume(password))
						{
							printf("Password match!\n");
							printf("NAME FILE: ");
							scanf("%s", &cFile);
							if (!ExistPasswordFile(cFile))
							{
								while (1)
								{
									printf("TYPE PASSWORD FILE: ");
									scanf("%s", &passwordFile);
									if (strlen(passwordFile) > 16) printf("Password is too long!\n");
									else break;
								}
								if (SetPasswordFile(passwordFile, cFile)) printf("Password file %s is set successfully!\n", cFile);
								else printf("Password file already existed!\n");
							}
							else printf("Cannot set password file because password file already existed!\n");
						}
						else printf("Password doesn't match!\n");
					}
					break;
				case 9:
					if (!havePasswordVolume)
					{
						printf("NAME FILE: ");
						scanf("%s", &cFile);
						if (!ExistPasswordFile(cFile)) printf("Cannot check password file because no password file!\n");
						else
						{
							while (1)
							{
								printf("TYPE PASSWORD FILE: ");
								scanf("%s", &passwordFile);
								if (strlen(passwordFile) > 16) printf("Password is too long!\n");
								else break;
							}
							if (CheckPasswordFile(passwordFile, cFile)) printf("Password file %s match!\n", cFile);
							else printf("Password file doesn't match!\n");
						}
					}
					else
					{
						while (1)
						{
							printf("TYPE PASSWORD: ");
							scanf("%s", &password);
							if (strlen(password) > 16) printf("Password is too long!\n");
							else break;
						}
						if (CheckPasswordVolume(password))
						{
							printf("Password match!\n");
							printf("NAME FILE: ");
							scanf("%s", &cFile);
							if (!ExistPasswordFile(cFile)) printf("Cannot check password file because no password file!\n");
							else
							{
								while (1)
								{
									printf("TYPE PASSWORD FILE: ");
									scanf("%s", &passwordFile);
									if (strlen(passwordFile) > 16) printf("Password is too long!\n");
									else break;
								}
								if (CheckPasswordFile(passwordFile, cFile)) printf("Password file %s match!\n", cFile);
								else printf("Password file doesn't match!\n");
							}
						}
						else printf("Password doesn't match!\n");
					}
					break;
				case 10:
					if (!havePasswordVolume)
					{
						printf("NAME FILE: ");
						scanf("%s", &cFile);
						if (!ExistPasswordFile(cFile)) printf("Cannot change password file because no password file!\n");
						else
						{
							while (1)
							{
								printf("TYPE OLD PASSWORD FILE: ");
								scanf("%s", &passwordFile);
								if (strlen(passwordFile) > 16) printf("Password is too long!\n");
								else break;
							}
							if (CheckPasswordFile(passwordFile, cFile))
							{
								while (1)
								{
									printf("TYPE NEW PASSWORD FILE: ");
									scanf("%s", &passwordFile);
									if (strlen(passwordFile) > 16) printf("Password is too long!\n");
									else break;
								}
								if (ChangePasswordFile(passwordFile, cFile)) printf("Password file %s is changed!\n", cFile);
								else printf("Password file is the same\n");
							}
							else printf("Password file doesn't match!\n");
						}
					}
					else
					{
						while (1)
						{
							printf("TYPE PASSWORD: ");
							scanf("%s", &password);
							if (strlen(password) > 16) printf("Password is too long!\n");
							else break;
						}
						if (CheckPasswordVolume(password))
						{
							printf("Password match!\n");
							printf("NAME FILE: ");
							scanf("%s", &cFile);
							if (!ExistPasswordFile(cFile)) printf("Cannot change password file because no password file!\n");
							else
							{
								while (1)
								{
									printf("TYPE OLD PASSWORD FILE: ");
									scanf("%s", &passwordFile);
									if (strlen(passwordFile) > 16) printf("Password is too long!\n");
									else break;
								}
								if (CheckPasswordFile(passwordFile, cFile))
								{
									while (1)
									{
										printf("TYPE NEW PASSWORD FILE: ");
										scanf("%s", &passwordFile);
										if (strlen(passwordFile) > 16) printf("Password is too long!\n");
										else break;
									}
									if (ChangePasswordFile(passwordFile, cFile)) printf("Password file %s is changed!\n", cFile);
									else printf("Password file is the same\n");
								}
								else printf("Password file doesn't match!\n");
							}
						}
						else printf("Password doesn't match!\n");
					}
					break;
				case 11:
					if (!havePasswordVolume)
					{
						printf("NAME FILE: ");
						scanf("%s", &cFile);
						if (!ExistPasswordFile(cFile)) printf("Cannot remove password file because no password file!\n");
						else
						{
							while (1)
							{
								printf("TYPE PASSWORD FILE: ");
								scanf("%s", &passwordFile);
								if (strlen(passwordFile) > 16) printf("Password is too long!\n");
								else break;
							}
							if (CheckPasswordFile(passwordFile, cFile))
							{
								if (RemovePasswordFile(cFile)) printf("Password file %s is reset!\n", cFile);
								else printf("\n");
							}
							else printf("Password file doesn't match!\n");
						}
					}
					else
					{
						while (1)
						{
							printf("TYPE PASSWORD: ");
							scanf("%s", &password);
							if (strlen(password) > 16) printf("Password is too long!\n");
							else break;
						}
						if (CheckPasswordVolume(password))
						{
							printf("Password match!\n");
							printf("NAME FILE: ");
							scanf("%s", &cFile);
							if (!ExistPasswordFile(cFile)) printf("Cannot remove password file because no password file!\n");
							else
							{
								while (1)
								{
									printf("TYPE PASSWORD FILE: ");
									scanf("%s", &passwordFile);
									if (strlen(passwordFile) > 16) printf("Password is too long!\n");
									else break;
								}
								if (CheckPasswordFile(passwordFile, cFile))
								{
									if (RemovePasswordFile(cFile)) printf("Password file %s is reset!\n", cFile);
									else printf("\n");
								}
								else printf("Password file doesn't match!\n");
							}
						}
						else printf("Password doesn't match!\n");
					}
					break;
				case 12:
					if (!havePasswordVolume)
					{
						printf("IMPORT FILE: ");
						scanf("%s", &cFile);
						if (ImportFile(cFile)) printf("Importing file %s successfully!\n", cFile);
						else printf("File is not existed!\n");
					}
					else
					{
						while (1)
						{
							printf("TYPE PASSWORD: ");
							scanf("%s", &password);
							if (strlen(password) > 16) printf("Password is too long!\n");
							else break;
						}
						if (CheckPasswordVolume(password))
						{
							printf("Password match!\n");
							printf("IMPORT FILE: ");
							scanf("%s", &cFile);
							if (ImportFile(cFile)) printf("Importing file %s successfully!\n", cFile);
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
						if (!ExistPasswordFile(cFile))
						{
							if (OutportFile(cFile)) printf("Outporting file %s successfully!\n", cFile);
							else printf("File is not existed!\n");
						}
						else
						{
							while (1)
							{
								printf("TYPE PASSWORD FILE: ");
								scanf("%s", &passwordFile);
								if (strlen(passwordFile) > 16) printf("Password is too long!\n");
								else break;
							}
							if (CheckPasswordFile(passwordFile, cFile))
							{
								if (OutportFile(cFile)) printf("Outporting file %s successfully!\n", cFile);
								else printf("File is not existed!\n");
							}
							else printf("Password doesn't match!\n");
						}
					}
					else
					{
						while (1)
						{
							printf("TYPE PASSWORD: ");
							scanf("%s", &password);
							if (strlen(password) > 16) printf("Password is too long!\n");
							else break;
						}
						if (CheckPasswordVolume(password))
						{
							printf("Password match!\n");
							printf("OUTPORT FILE: ");
							scanf("%s", &cFile);
							if (!ExistPasswordFile(cFile))
							{
								if (OutportFile(cFile)) printf("Outporting file %s successfully!\n", cFile);
								else printf("File is not existed!\n");
							}
							else
							{
								while (1)
								{
									printf("TYPE PASSWORD FILE: ");
									scanf("%s", &passwordFile);
									if (strlen(passwordFile) > 16) printf("Password is too long!\n");
									else break;
								}
								if (CheckPasswordFile(passwordFile, cFile))
								{
									if (OutportFile(cFile)) printf("Outporting file %s successfully!\n", cFile);
									else printf("File is not existed!\n");
								}
								else printf("Password doesn't match!\n");
							}
						}
						else printf("Password doesn't match!\n");
					}
					break;
				case 14:
					if (!havePasswordVolume)
					{
						printf("DELETED FILE: ");
						scanf("%s", &cFile);
						if (!ExistPasswordFile(cFile))
						{
							if (DeletedFile(cFile)) printf("Deleting file %s successfully\n", cFile);
							else printf("File is not existed!\n");
						}
						else
						{
							while (1)
							{
								printf("TYPE PASSWORD FILE: ");
								scanf("%s", &passwordFile);
								if (strlen(passwordFile) > 16) printf("Password is too long!\n");
								else break;
							}
							if (CheckPasswordFile(passwordFile, cFile))
							{
								if (DeletedFile(cFile)) printf("Deleting file %s successfully\n", cFile);
								else printf("File is not existed!\n");
							}
							else printf("Password doesn't match!\n");
						}
					}
					else
					{
						while (1)
						{
							printf("TYPE PASSWORD: ");
							scanf("%s", &password);
							if (strlen(password) > 16) printf("Password is too long!\n");
							else break;
						}
						if (CheckPasswordVolume(password))
						{
							printf("Password match!\n");
							printf("DELETED FILE: ");
							scanf("%s", &cFile);
							if (!ExistPasswordFile(cFile))
							{
								if (DeletedFile(cFile)) printf("Deleting file %s successfully\n", cFile);
								else printf("File is not existed!\n");
							}
							else
							{
								while (1)
								{
									printf("TYPE PASSWORD FILE: ");
									scanf("%s", &passwordFile);
									if (strlen(passwordFile) > 16) printf("Password is too long!\n");
									else break;
								}
								if (CheckPasswordFile(passwordFile, cFile))
								{
									if (DeletedFile(cFile)) printf("Deleting file %s successfully\n", cFile);
									else printf("File is not existed!\n");
								}
								else printf("Password doesn't match!\n");
							}
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