#include <Windows.h>
#include <WinCrypt.h>
#include <stdio.h>
#include <string>

#pragma comment(lib, "crypt32.lib")

#define snprintf _snprintf
#define MAX_BUF_SIZE 1024
#define VERSION "1.0"

using namespace std;

class EncryptFileClass
{
public:
	BOOL AES(char *pPassword, char **pData, DWORD pDataSize, long *pOutputSize);
	void Encrypt(char* file, char* password);
};