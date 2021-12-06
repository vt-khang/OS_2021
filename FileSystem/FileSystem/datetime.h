#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "conv.h"
#include "string_s.h"

// Declaration of structures
struct Date
{
	int day;
	int month;
	int year;
};
struct Time
{
	int hour;
	int minute;
	int second;
};

// Declaration of functions
Date _GetCurrentDate();
Time _GetCurrentTime();
Date InitializeDate(int day, int month, int year);
Time InitializeTime(int hour, int minute, int second);
void Print(Date date);
void Print(Time time);
Date ScanDate(const char* str);
Time ScanTime(const char* str);
char* Date2Hex(Date date);
char* Time2Hex(Time time);
Date Hex2Date(const char* hex);
Time Hex2Time(const char* hex);
Date GetCreatedFileDate(const char* file);
Time GetCreatedTimeFile(const char* file);
Date GetModifiedDateFile(const char* file);
Time GetModifiedTimeFile(const char* file);
Date GetAccessDateFile(const char* file);
Time GetAccessTimeFile(const char* file);

// Get the current date
Date _GetCurrentDate()
{
	Date CurrentDate;
	time_t t = time(0);
	tm* now = localtime(&t);
	CurrentDate.day = now->tm_mday;
	CurrentDate.month = now->tm_mon + 1;
	CurrentDate.year = now->tm_year + 1900;
	return CurrentDate;
}

// Get the current time
Time _GetCurrentTime()
{
	Time CurrentTime;
	time_t t = time(0);
	tm* now = localtime(&t);
	CurrentTime.hour = now->tm_hour;
	CurrentTime.minute = now->tm_min;
	CurrentTime.second = now->tm_sec;
	return CurrentTime;
}

// Initialize date by input
Date InitializeDate(int day, int month, int year)
{
	Date date;
	date.day = day;
	date.month = month;
	date.year = year;
	return date;
}

// Initialize time by input
Time InitializeTime(int hour, int minute, int second)
{
	Time time;
	time.hour = hour;
	time.minute = minute;
	time.second = second;
	return time;
}

// Print date
void Print(Date date)
{
	printf("%d-%d-%d", date.day, date.month, date.year);
}

// Print time
void Print(Time time)
{
	printf("%d:%d:%d", time.hour, time.minute, time.second);
}

// Scan date
Date ScanDate(const char* str)
{
	Date date;
	date.day = atoi(strsub(str, 0, strfind(str, '-')));
	char* s1 = strsub(str, strfind(str, '-') + 1);
	date.month = atoi(strsub((const char*)s1, 0, strfind(s1, '-')));
	char* s2 = strsub(s1, strfind(s1, '-') + 1);
	date.year = atoi(s2);
	return date;
}

// Scan time
Time ScanTime(const char* str)
{
	Time time;
	time.hour = atoi(strsub(str, 0, strfind(str, ':')));
	char* s1 = strsub(str, strfind(str, ':') + 1);
	time.minute = atoi(strsub((const char*)s1, 0, strfind(s1, ':')));
	char* s2 = strsub(s1, strfind(s1, ':') + 1);
	time.second = atoi(s2);
	return time;
}

// Convert date to hexadecimal
char* Date2Hex(Date date)
{
	char bin[16 + 1];
	strcpy(bin, BinResize(Dec2Bin(date.day), 5));
	strcat(bin, BinResize(Dec2Bin(date.month), 4));
	strcat(bin, BinResize(Dec2Bin(date.year - 1900), 7));
	return Bin2Hex((const char*)bin);
}

// Convert time to hexadecimal
char* Time2Hex(Time time)
{
	char bin[16 + 1];
	strcpy(bin, BinResize(Dec2Bin(time.hour), 5));
	strcat(bin, BinResize(Dec2Bin(time.minute), 6));
	strcat(bin, BinResize(Dec2Bin((int)time.second / 2), 5));
	return Bin2Hex((const char*)bin);
}

// Convert hexadecimal to date
Date Hex2Date(const char* hex)
{
	Date date;
	date.day = Bin2Dec(strsub(Hex2Bin(hex), 0, 5));
	date.month = Bin2Dec(strsub(Hex2Bin(hex), 5, 4));
	date.year = Bin2Dec(strsub(Hex2Bin(hex), 9, 7)) + 1900;
	return date;
}

// Convert hexadecimal to time
Time Hex2Time(const char* hex)
{
	Time time;
	time.hour = Bin2Dec(strsub(Hex2Bin(hex), 0, 5));
	time.minute = Bin2Dec(strsub(Hex2Bin(hex), 5, 6));
	time.second = Bin2Dec(strsub(Hex2Bin(hex), 11, 5)) * 2;
	return time;
}

// Get created date of file
Date GetCreatedDateFile(const char* file)
{
	struct stat attr;
	stat(file, &attr);
	char date[MAX];
	strftime(date, MAX, "%d-%m-%Y", localtime(&(attr.st_ctime)));
	return ScanDate(date);
}

// Get created time of file
Time GetCreatedTimeFile(const char* file)
{
	struct stat attr;
	stat(file, &attr);
	char time[MAX];
	strftime(time, MAX, "%H:%M:%S", localtime(&(attr.st_ctime)));
	return ScanTime(time);
}

// Get modified date of file
Date GetModifiedDateFile(const char* file)
{
	struct stat attr;
	char date[MAX];
	stat(file, &attr);
	strftime(date, MAX, "%d-%m-%Y", localtime(&attr.st_mtime));
	return ScanDate(date);
}

// Get modified time of file
Time GetModifiedTimeFile(const char* file)
{
	struct stat attr;
	char time[MAX];
	stat(file, &attr);
	strftime(time, MAX, "%H:%M:%S", localtime(&attr.st_mtime));
	return ScanTime(time);
}

// Get access date of file
Date GetAccessDateFile(const char* file)
{
	struct stat attr;
	char date[MAX];
	stat(file, &attr);
	strftime(date, MAX, "%d-%m-%Y", localtime(&attr.st_atime));
	return ScanDate(date);
}

// Get access time of file
Time GetAccessTimeFile(const char* file)
{
	struct stat attr;
	char time[MAX];
	stat(file, &attr);
	strftime(time, MAX, "%H:%M:%S", localtime(&attr.st_atime));
	return ScanTime(time);
}