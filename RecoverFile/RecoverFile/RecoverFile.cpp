#define _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_DEPRECATE
#define _CRT_NONSTDC_NO_DEPRECATE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <Windows.h>
#include <cwchar>
#include <vector>
#define VOLUME		'F'
#define OFFSET_CLUS	4
#define RETRY_SIZE	32
#define MAX			100
#define SEC_SIZE	512

// Declaration of functions
int Length(int number);
int Hex2Dec(const char* hex);
char* Dec2Hex(int dec);
bool ReadSector(int numSector, unsigned char* buf);
bool WriteSector(int numSector, unsigned char* buf);
char* ReadOffset(unsigned char* sector, const char* offset, int numBytes);
void WriteOffset(unsigned char* sector, const char* offset, const char* description);
void Print(unsigned char* sector);
char* ReadFat(int cluster);
unsigned char* WriteFat(int cluster, const char* description);
int IndexCluster(int cluster);
int IndexSector(int sector);

// Declaration of variables
int byteSector;
int sectorClus;
int sectorBoot;
int numFat;
int numEntry;
int sectorVol;
int clusterVol;
int sectorFat;
int RDET;
int sectorSystem;
int sectorData;

// Length of number
int Length(int number)
{
	if (number == 0) return 1;
	return floor(log10(abs(number))) + 1;
}

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

// Read specific sector on hard drive
bool ReadSector(int numSector, unsigned char* buf)
{
	bool retCode = false;
	unsigned char sector[SEC_SIZE];
	DWORD bytesRead;
	HANDLE hDevice = NULL;

	wchar_t deviceName[MAX];
	swprintf(deviceName, sizeof(deviceName), L"\\\\.\\%c:", VOLUME);

	hDevice = CreateFile(deviceName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hDevice == INVALID_HANDLE_VALUE)
		return false;
	else
	{
		SetFilePointer(hDevice, numSector * SEC_SIZE, NULL, FILE_BEGIN);
		if (!ReadFile(hDevice, sector, SEC_SIZE, &bytesRead, NULL))
			printf("Error in reading disk\n");
		else
		{
			// Copy boot sector into buffer and set retCode
			memcpy(buf, sector, SEC_SIZE);
			retCode = true;
		}
		// Close the handle
		CloseHandle(hDevice);
	}
	return retCode;
}

// Write specific sector on hard drive
bool WriteSector(int numSector, unsigned char* buf)
{
	bool retCode = false;
	unsigned char sector[SEC_SIZE];
	DWORD bytesWrite;
	DWORD status;
	HANDLE hDevice = NULL;

	wchar_t deviceName[MAX];
	swprintf(deviceName, sizeof(deviceName), L"\\\\.\\%c:", VOLUME);

	hDevice = CreateFile(deviceName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hDevice == INVALID_HANDLE_VALUE)
		return false;
	else
	{
		// Dismout and lock
		if (!DeviceIoControl(hDevice, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &status, NULL))
			printf("Error in writing disk\n");
		// Lock volume
		if (!DeviceIoControl(hDevice, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &status, NULL))
			printf("Error in writing disk\n");

		SetFilePointer(hDevice, numSector * SEC_SIZE, NULL, FILE_BEGIN);
		if (!WriteFile(hDevice, buf, SEC_SIZE, &bytesWrite, NULL))
			printf("Error in writing disk\n");
		else
			retCode = true;
		CloseHandle(hDevice);
	}
	return retCode;
}

// Read offset by sector index
char* ReadOffset(unsigned char* sector, const char* offset, int numBytes)
{
	unsigned char* buf = (unsigned char*)malloc(numBytes * sizeof(unsigned char*));
	for (int i = Hex2Dec(offset); i < Hex2Dec(offset) + numBytes; i++)
		buf[numBytes - 1 - (i - Hex2Dec(offset))] = sector[i];

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

// Write offset by sector index
void WriteOffset(unsigned char* sector, const char* offset, const char* description)
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
	for (int i = Hex2Dec(offset); i < Hex2Dec(offset) + numBytes; i++)
		sector[i] = buf[numBytes - 1 - (i - Hex2Dec(offset))];
	free(buf);
}

// Print sector
void Print(unsigned char* sector)
{
	for (int i = 0; i < SEC_SIZE; i++)
	{
		printf("%02x ", sector[i]);
		if (i % 16 == 15) printf("\n");
	}
}

// Next cluster in FAT table
char* ReadFat(int cluster)
{
	unsigned char* sector = (unsigned char*)malloc(SEC_SIZE * sizeof(unsigned char*));
	ReadSector(cluster / (byteSector / OFFSET_CLUS) + sectorBoot, sector);

	char* res = (char*)malloc(OFFSET_CLUS * 2 * sizeof(char*));
	res = ReadOffset(sector, Dec2Hex(cluster % (byteSector / OFFSET_CLUS) * OFFSET_CLUS), OFFSET_CLUS);
	return res;
}

// Write cluster by FAT table
unsigned char* WriteFat(int cluster, const char* description)
{
	unsigned char* sector = (unsigned char*)malloc(SEC_SIZE * sizeof(unsigned char*));
	ReadSector(cluster / (byteSector / OFFSET_CLUS) + sectorBoot, sector);

	WriteOffset(sector, Dec2Hex(cluster % (byteSector / OFFSET_CLUS) * OFFSET_CLUS), description);
	return sector;
}

// Index of cluster (= sector)
int IndexCluster(int cluster)
{
	return sectorSystem + (cluster - RDET) * sectorClus;
}

// Index of sector (= cluster)
int IndexSector(int sector)
{
	return (sector - sectorSystem) / sectorClus + RDET;
}

int main()
{
	// Boot sector
	unsigned char* BootSector = (unsigned char*)malloc(SEC_SIZE * sizeof(unsigned char*));
	if (!ReadSector(0, BootSector))
		exit(1);

	byteSector = Hex2Dec((char*)ReadOffset(BootSector, "B", 2));
	sectorClus = Hex2Dec((char*)ReadOffset(BootSector, "D", 1));
	sectorBoot = Hex2Dec((char*)ReadOffset(BootSector, "E", 2));
	numFat = Hex2Dec((char*)ReadOffset(BootSector, "10", 1));
	numEntry = Hex2Dec((char*)ReadOffset(BootSector, "11", 2));
	sectorVol = Hex2Dec((char*)ReadOffset(BootSector, "20", 4));
	sectorFat = Hex2Dec((char*)ReadOffset(BootSector, "24", 4));
	RDET = Hex2Dec((char*)ReadOffset(BootSector, "2C", 4));
	sectorSystem = sectorBoot + numFat * sectorFat + numEntry;
	sectorData = sectorVol - sectorSystem;
	clusterVol = sectorData / sectorClus;

	free(BootSector);

	// Find all entry in volume and recover deleted file
	bool retCode = false;
	int fatTab = RDET;
	int sectorEntry = sectorSystem;
	while (1)
	{
		for (int indexSector = sectorEntry; indexSector < sectorEntry + sectorClus; indexSector++)
		{
			unsigned char* Entry = (unsigned char*)malloc(SEC_SIZE * sizeof(unsigned char*));
			ReadSector(indexSector, Entry);

			for (int offset = 0; offset < SEC_SIZE; offset += RETRY_SIZE)
			{
				if (Entry[offset] == 0x00) {
					retCode = true; break;
				}
				if (Entry[offset] == 0xe5)
				{
					WriteOffset(Entry, Dec2Hex(offset), "46");

					int retrySize = Hex2Dec(ReadOffset(Entry, Dec2Hex(offset + 28), 4));
					int clusterEntry = ceil(retrySize / (float)byteSector) / sectorClus;
					int startCluster = Hex2Dec(ReadOffset(Entry, Dec2Hex(offset + 26), 2));

					unsigned char* entryFat = (unsigned char*)malloc(SEC_SIZE * sizeof(unsigned char*));
					for (int cluster = startCluster; cluster < startCluster + clusterEntry; cluster++)
					{
						if (cluster == startCluster + clusterEntry - 1)
							entryFat = WriteFat(cluster, "0fffffff");
						else
							entryFat = WriteFat(cluster, Dec2Hex(cluster + 1));
						WriteSector(sectorBoot + cluster / (byteSector / OFFSET_CLUS), entryFat);
					}
					free(entryFat);
				}
			}
			WriteSector(indexSector, Entry);

			free(Entry);
			if (retCode) break;
		}
		if (Hex2Dec(ReadFat(fatTab)) == Hex2Dec("0fffffff")) break;
		else sectorEntry = IndexCluster(Hex2Dec(ReadFat(fatTab)));
		fatTab = Hex2Dec(ReadFat(fatTab));
	}

	return 0;
}