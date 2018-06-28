#include <Windows.h>
#include <WinHttp.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include <cctype>
#include <functional> 

#pragma comment(lib, "winhttp.lib")

using namespace std;

class HTTP
{
public:
	string Request(string domain, string url, string dat, string method);
private:
	std::wstring get_utf16(const std::string &str, int codepage);
};