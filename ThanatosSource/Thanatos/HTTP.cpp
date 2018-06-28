#include "HTTP.h"
#include "Utils.h"

std::wstring HTTP::get_utf16(const std::string &str, int codepage)
{
	if (str.empty()) return std::wstring();
	int sz = MultiByteToWideChar(codepage, 0, &str[0], (int)str.size(), 0, 0);
	std::wstring res(sz, 0);
	MultiByteToWideChar(codepage, 0, &str[0], (int)str.size(), &res[0], sz);
	return res;
}

string HTTP::Request(string domain, string url, string dat, string method)
{
	Utils utils;
	LPSTR  data = const_cast<char *>(dat.c_str());;
	DWORD data_len = strlen(data);

	wstring sdomain = get_utf16(domain, CP_UTF8);
	wstring surl = get_utf16(url, CP_UTF8);
	string response;

	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	LPSTR pszOutBuffer;
	BOOL  bResults = FALSE;
	HINTERNET  hSession = NULL,
		hConnect = NULL,
		hRequest = NULL;

	hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 6.1) Thanatos/1.1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

	if (hSession)
		hConnect = WinHttpConnect(hSession, sdomain.c_str(), INTERNET_DEFAULT_HTTP_PORT, 0);

	if (hConnect)
		hRequest = WinHttpOpenRequest(hConnect, utils.s2ws(method).c_str(), surl.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

	if (hRequest)
		bResults = WinHttpSendRequest(hRequest, L"Content-Type: application/x-www-form-urlencoded\r\n", (DWORD)-1, (LPVOID)data, data_len, data_len, 0);


	if (bResults)
		bResults = WinHttpReceiveResponse(hRequest, NULL);

	if (bResults)
	{
		do
		{
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {}

			pszOutBuffer = new char[dwSize + 1];
			if (!pszOutBuffer)
			{
				dwSize = 0;
			}
			else
			{
				ZeroMemory(pszOutBuffer, dwSize + 1);

				if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) {}
				else
					response = response + string(pszOutBuffer);
				delete[] pszOutBuffer;
			}
		} while (dwSize > 0);
	}

	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);

	return response;
}