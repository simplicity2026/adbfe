#define _WIN32_WINNT 0x0501
#define _WIN32_IE 0x0600
#ifndef LVN_COLUMNWIDTHCHANGED
#define LVN_COLUMNWIDTHCHANGED (LVN_FIRST - 25)
#endif
#define APP_TITLE2 "ADB File Explorer"
#define MAX_ENTRIES 5000
#define MAX_NAME_LENGTH 256

#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <sstream>
#include <iostream>
#include <CommCtrl.h>
#pragma comment(lib, "Comctl32.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#include <uxtheme.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <windowsx.h>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <ctime>
#include <direct.h>
#include <shlobj.h>
#include <thread>
#include <commdlg.h>
#include <regex>
#include <psapi.h>
#include <unordered_set>

std::string GetProgramDir(unsigned int PDID);
std::string adbPath;
std::string LS_PATH = "/sdcard/", FE_CMD = "shell ls -l -a";

bool file_exists(const std::string& fullpath);
bool isProcessRunning(const std::string& processName);
std::string exeFROMisProcessRunning;
bool isADBconnected(void);
bool ADBconnected = false;
std::string escapeShellChars(const std::string& path);
std::string getADBOutput();

struct FileEntry {
	std::string Type;
	long long Size;
	std::string FormattedSize;
	std::string DateTime;
	std::string Name;
};

std::vector<FileEntry> entries;
std::vector<FileEntry> parseFileList(const std::string& result);

HWND hListViewWindow1, hListView1, hListViewStatus1;
void DrawListViewCell(HDC hdc, RECT rc, int row, int col, bool selected, bool reverse);
LRESULT CALLBACK hListViewWindow1Proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
WNDPROC g_oldListView1Proc = nullptr;
LRESULT CALLBACK CustomListView1Proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

HMENU hMenu1, hFileMenu1;
HWND hToolBar1, hStatusBar1, hBtnUp1, hBtnOpen1, hBtnDownload1, hBtnUploadFile1, hBtnUploadFolder1, hBtnDelete1, hBtnSettings1, hBtnLog1;
std::string status_text1, status_text2, status_text3;
HICON LoadShellIcon(LPCSTR dllName, int index, int size);
WNDPROC g_oldToolBar1Proc = nullptr, g_oldStatusBar1Proc = nullptr;
LRESULT CALLBACK hToolBar1Proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT CALLBACK StatusBar1Proc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
std::string adb_status1 = "ADB Device is Offline";

void StartFEWindow(HINSTANCE hInst, int nCmdShow);
void PopulateListView(void);
HICON get_icon_for_file(const char* filename, const char* ItemType);
std::vector<bool> g_checked;
int g_selectedRow = -1;

bool IsAnyCheckboxChecked();
bool IsPointInCheckbox(HWND hwnd, int row, POINT pt);
void ToggleCheckbox(HWND hwnd, int row);
void ClearNormalSelection(HWND hwnd);
void HandleNormalClickSelection(HWND hwnd, int row);
int g_hoveredRow = -1;
bool g_trackingMouse = false;
void UpdateHoveredRow(HWND hListView, POINT pt);
void ClearHoveredRowIfSelectedOrChecked(HWND hwnd);

int LV1_LastSortColumn = -1;
bool LV1_SortAscending = true;
bool reverse_list = false;
void SortFileEntries(void);
void SetSortArrow(void);

std::string GetSDParentDir(const std::string& path);
void ReplaceChars(std::string& str, const std::string& find, const std::string& replace);
std::string GetFileNameFromPath(const std::string& androidPath);
std::string GetFileExtension(const std::string& fileName);
std::string GetExeFolder(void);
std::string GetexePath(void);
void RunCommandAsync(const std::string& cmd, bool HideProcess, std::string ExplorerDirRunAfter);
void OpenItem(const std::string& Path, const std::string& Type, long long SizeInBytes);

void DisableItemButtons1(void);
void EnableItemButtons1(void);
int SelectedIndex, maxDisplayChars = 65;;
std::vector<std::string> selectedItems;
std::string formatFileSize(long long SizeInBytes);
std::string DefineFileType(const std::string& File);
std::vector<int> GetSelectedIndices(void);
std::pair<std::vector<std::string>, std::vector<std::string>> GetSelectedPathsAndTypes(void);
void UpdateStatusBarSelection(void);

void ReWriteLineBreaksByExtension(const std::string& filePath);
std::string BrowseForFile(void);
std::string BrowseForFolder(void);
void TryDownloading(void);
void TryUploading(unsigned int itype);
void TryDeleting(void);
int g_listViewIndex = -1;

void SaveMainWindowSettings(bool sendlog);
void RestoreMainWindowSettings(void);
std::string GRSS(const std::string& name, const std::string& defaultValue);
void WRSS(const std::string& name, const std::string& value);
bool AllowSaveMainWindowSettings;

void LOG_THIS(std::string content);
bool FontExists(const char* fontName);
void RefreshTheLogView1(void);
void DeleteAllLogs1(void);
bool FUNC1Running = false;
void PRELOADFL(void);

void StartSettingsWindow1(void);
LRESULT CALLBACK SettingsWindow1Proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
HWND hSettingsWindow1, hSettingsWindow1ADBPath1, hSettingsWindow1BrowseBTN1, hSettingsWindow1DefaultBTN1, hSW1rmwpCB1, hSW1epciscCB1, hSW1rwlbCB1, hSW1sbofdiCB1, hSW1cbpCB1, hSW1usctoiCB1;

WNDPROC g_oldSW1rmwpCB1Proc = nullptr, g_oldSW1epciscCB1Proc = nullptr, g_oldSW1rwlbCB1Proc = nullptr, g_oldSW1sbofdiCB1Proc = nullptr, g_oldSW1cbpCB1Proc = nullptr, g_oldSW1usctoiCB1Proc = nullptr;

LRESULT CALLBACK SW1rmwpCB1Proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK SW1epciscCB1Proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK SW1rwlbCB1Proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK SW1sbofdiCB1Proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK hSW1cbpCB1Proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK SW1usctoiCB1Proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

void StartLogViewWindow1(void);
LRESULT CALLBACK LogViewWindow1Proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
HWND hLogViewWindow1, hLogViewTextEdit1, hRfreshLVButton1, hCALButton1, hEnableLoggingLabel1, hEnableLoggingCheckbox1;

WNDPROC g_oldCheckbox1Proc = nullptr;
LRESULT CALLBACK Checkbox1Proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

bool execTimer1 = true;
bool execTimer2 = true;
void CALLBACK Timer1Proc(HWND hwnd, UINT msg, UINT_PTR id, DWORD time);
void CALLBACK Timer2Proc(HWND hwnd, UINT msg, UINT_PTR id, DWORD time);
void CALLBACK Timer3Proc(HWND hwnd, UINT msg, UINT_PTR id, DWORD time);

bool flashStatus = true;
bool flashVisible = true;
COLORREF flashColor = RGB(255, 25, 25);
COLORREF normalColor = RGB(91, 253, 176);

bool SW1rmwpCB1 = true, SW1epciscCB1 = true, SW1rwlbCB1 = true, SW1sbofdiCB1 = false, SW1cbpCB1 = true, SW1usctoiCB1 = false;
bool FUNC2Running = false;

std::string getOfflineFL(std::string sdcard_Path);
void saveOfflineFL(std::string sdcard_Path, std::string FL_data);
std::string FindCopyOfFile(std::string filename, long long SizeInBytes);
bool IsWindowTopMost(HWND hWnd);
bool EnableLoggingCB1 = true;
void DeleteAllLogs1(void);
void MoveWithoutErase(const std::string& cmd);
const int maxFLFsize = 2 * 1024 * 1024;
void cleanupOfflineFLF(void);

/// DEFINITIONS ///

void MBD(const char* MSG_ = "Debug") {
    MessageBoxA(NULL, MSG_, APP_TITLE2, MB_OK | MB_ICONINFORMATION);
}

bool file_exists(const std::string& fullpath)
{
	DWORD attr = GetFileAttributesA(fullpath.c_str());
	return (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY));
}

bool isProcessRunning(const std::string& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return false;
    }

    do {
        if (processName == pe32.szExeFile) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            if (hProcess != NULL) {
                DWORD waitResult = WaitForSingleObject(hProcess, 5000); // 5s timeout
                if (waitResult == WAIT_OBJECT_0) {
                    // Process has exited
                    CloseHandle(hProcess);
                    CloseHandle(hSnapshot);
                    return false;
                }

                char buffer[MAX_PATH];
                if (GetModuleFileNameExA(hProcess, NULL, buffer, MAX_PATH)) {
                    exeFROMisProcessRunning = buffer;
                    CloseHandle(hProcess);
                    CloseHandle(hSnapshot);
                    return true;
                }
                CloseHandle(hProcess);
            }
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return false;
}

bool isADBconnected(void)
{
	if (adbPath.empty()) return false; // Check if adbPath is set

	std::string cmd = "\"" + adbPath + "\" devices";
	SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
	HANDLE hRead, hWrite;
	if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return false;

	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFOA si = { sizeof(STARTUPINFOA) };
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdOutput = hWrite;
	si.hStdError = hWrite;
	if (!CreateProcessA(NULL, (LPSTR)cmd.c_str(), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
		CloseHandle(hRead);
		CloseHandle(hWrite);
		return false;
	}

	CloseHandle(hWrite);

	char buffer[128];
	std::string output;
	DWORD bytesRead;
	while (ReadFile(hRead, buffer, 128, &bytesRead, NULL) && bytesRead > 0) {
		output.append(buffer, bytesRead);
	}
	CloseHandle(hRead);
	WaitForSingleObject(pi.hProcess, 7000);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	// Check if there's at least one device connected
	return output.find("List of devices attached") != std::string::npos &&
	       output.find("\n") != std::string::npos && // Ensure there's at least one newline
	       output.find("\n") != output.rfind("\n") && // Ensure there's more than one line
	       output.find("device", output.find("\n") + 1) != std::string::npos;

}

std::string escapeShellChars(const std::string& path)
{
	if(!SW1epciscCB1) {
		return path;
	}
	
	std::string escapedPath;
	for (char c : path) {
		switch (c) {
		case ' ':
		case '(':
		case ')':
		case '&':
		case ';':
		case '|':
		case '>':
		case '<':
		case '*':
		case '?':
		case '$':
		case '{':
		case '}':
		case '[':
		case ']':
		case '-':
			escapedPath += '\\';
		// fall through
		default:
			escapedPath += c;
		}
	}
	return escapedPath;
}

std::string getOfflineFL(std::string sdcard_Path) {
	std::string offlineFLdir = GetProgramDir(0) + "OFFLINEFILELISTS\\";
    std::string FLdatafile = offlineFLdir + "main.txt";
    if(sdcard_Path.empty() || !file_exists(FLdatafile)) {
        return "";
    }
    HANDLE hFile = CreateFileA(FLdatafile.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return "";
    }
    DWORD fileSize = GetFileSize(hFile, NULL);
    char* buffer = new char[fileSize + 1];
    DWORD bytesRead;
    ReadFile(hFile, buffer, fileSize, &bytesRead, NULL);
    buffer[fileSize] = '\0';
    CloseHandle(hFile);
    std::string data(buffer);
    delete[] buffer;
    std::vector<std::string> lines;
    size_t pos = 0;
    while ((pos = data.find("\r\n")) != std::string::npos) {
        lines.push_back(data.substr(0, pos));
        data.erase(0, pos + 2);
    }
    if (!data.empty()) {
        lines.push_back(data);
    }

    for (int i = lines.size() - 1; i >= 0; --i) {
        if (lines[i].find(sdcard_Path) == 0) {
			LOG_THIS("[ std::string getOfflineFL(.) ] Stored File List found...\r\n");
            return lines[i].substr(sdcard_Path.length());
        }
    }
	LOG_THIS("[ std::string getOfflineFL(.) ] Stored File List not found...\r\n");
    return "";
}

void saveOfflineFL(std::string sdcard_Path, std::string FL_data) {
    if(sdcard_Path.empty()) {
        return;
    }
    std::string offlineFLdir = GetProgramDir(0) + "OFFLINEFILELISTS\\";
    SHCreateDirectoryEx(NULL, offlineFLdir.c_str(), NULL); // Ensure directory exists
    std::string FLdatafile = offlineFLdir + "main.txt";
    HANDLE hFile = CreateFileA(FLdatafile.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        std::string data_entry = sdcard_Path + "===" + FL_data + "\r\n";
        DWORD bytesWritten;
        WriteFile(hFile, data_entry.c_str(), data_entry.length(), &bytesWritten, NULL);
        CloseHandle(hFile);
    }
}

bool ReadFileToString(const std::string& path, std::string& out) {
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD size = GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE || size == 0) {
        CloseHandle(hFile);
        return false;
    }

    out.resize(size);
    DWORD read = 0;
    ReadFile(hFile, &out[0], size, &read, NULL);
    CloseHandle(hFile);
    return (read == size);
}

bool WriteStringToFile(const std::string& path, const std::string& data) {
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_WRITE, 0, NULL,
	CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD written = 0;
    WriteFile(hFile, data.c_str(), (DWORD)data.size(), &written, NULL);
    CloseHandle(hFile);
    return (written == data.size());
}

// Utility: Split by any line ending (\n, \r\n, \r)
std::vector<std::string> SplitLines(const std::string& input) {
    std::vector<std::string> lines;
    size_t i = 0;
    while (i < input.size()) {
        size_t start = i;
        while (i < input.size() && input[i] != '\n' && input[i] != '\r') i++;
        lines.push_back(input.substr(start, i - start));
        if (i < input.size() && input[i] == '\r') i++;
        if (i < input.size() && input[i] == '\n') i++;
        else if (i < input.size() && input[i - 1] != '\n') i++; // lone \r
    }
    return lines;
}

void cleanupOfflineFLF(void)
{
    std::string offlineFLdir = GetProgramDir(0) + "OFFLINEFILELISTS\\";
    std::string FLdatafile = offlineFLdir + "main.txt";

    std::string content;
    if (!ReadFileToString(FLdatafile, content)) return;

    std::vector<std::string> lines = SplitLines(content);

    std::unordered_set<std::string> seen;
    std::vector<std::string> unique;
    for (const auto& line : lines) {
		if (!line.empty() && seen.insert(line).second)
            unique.push_back(line);
    }

    // Compute total size
    size_t totalSize = 0;
    for (const auto& line : unique)
        totalSize += line.size() + 2;

    if (totalSize > maxFLFsize) {
        size_t targetSize = maxFLFsize * 3 / 4;
        size_t currentSize = 0;
        std::vector<std::string> trimmed;

        for (int i = (int)unique.size() - 1; i >= 0; --i) {
            currentSize += unique[i].size() + 2;
            if (currentSize > targetSize) break;
            trimmed.push_back(unique[i]);
        }

        std::reverse(trimmed.begin(), trimmed.end());
        unique = std::move(trimmed);
    }

    std::string output;
    for (const auto& line : unique)
        output += line + "\r\n";

    WriteStringToFile(FLdatafile, output);
}

std::string getADBOutput()
{
	// Construct full adb command
	// note: escapeShellChars(.) is disabled by Settings inside function, check function...
	
	std::string cmd = "\"" + adbPath + "\" " + FE_CMD + " \"" + escapeShellChars(LS_PATH) + "\"";

	if(!ADBconnected && SW1cbpCB1) { return getOfflineFL(escapeShellChars(LS_PATH)+"==="); }

	SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
	HANDLE hRead = NULL, hWrite = NULL;

	if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
		MessageBoxA(NULL, "Error: Failed to create pipe to run the Android Debug Bridge.", APP_TITLE2, MB_ICONERROR);
		return {};
	}

	SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFOA si = { 0 };
	si.cb = sizeof(si);
	si.hStdError = hWrite;
	si.hStdOutput = hWrite;
	si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	// Use .data() to get mutable char* for CreateProcessA
	std::vector<char> cmdBuffer(cmd.begin(), cmd.end());
	cmdBuffer.push_back('\0');

	if (!CreateProcessA(NULL, cmdBuffer.data(), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
		MessageBoxA(NULL, "Error: Failed to start adb process.", APP_TITLE2, MB_ICONERROR);
		CloseHandle(hWrite);
		CloseHandle(hRead);
		return {};
	}
	CloseHandle(hWrite); // Close write end in parent

	std::string output;
	char buffer[256];
	DWORD bytesRead;
	while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
		buffer[bytesRead] = '\0';
		output += buffer;
	}

	CloseHandle(hRead);
	WaitForSingleObject(pi.hProcess, 5000);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	// Process output: Replace line breaks with \\\ unless already escaped
	std::ostringstream processed;
	size_t len = output.length();
	for (size_t i = 0; i < len;) {
		if (output[i] == '\r' || output[i] == '\n') {
			if (!processed.str().empty() && processed.str().back() != '\\') {
				processed << "\\\\\\";
			}
			while (i < len && (output[i] == '\r' || output[i] == '\n')) ++i;
		} else {
			processed << output[i++];
		}
	}

	std::string result = processed.str();
	if (result.size() >= 3 &&
	        result[result.size() - 3] == '\\' &&
	        result[result.size() - 2] == '\\' &&
	        result[result.size() - 1] == '\\') {
		result.erase(result.end() - 3, result.end());
	}

	saveOfflineFL(escapeShellChars(LS_PATH), result);
	
	return result;
}

std::vector<FileEntry> parseFileList(const std::string& result)
{
	std::vector<FileEntry> fileEntries;
	std::istringstream iss(result);
	std::string line;

	while (std::getline(iss, line, '\\')) {
		// Normalize spaces
		std::string normalizedLine;
		bool prevSpace = false;
		for (char c : line) {
			if (std::isspace(c)) {
				if (!prevSpace) {
					normalizedLine += ' ';
					prevSpace = true;
				}
			} else {
				normalizedLine += c;
				prevSpace = false;
			}
		}

		// Split entry by spaces
		std::istringstream entryStream(normalizedLine);
		std::vector<std::string> parts;
		std::string part;
		while (entryStream >> part) {
			parts.push_back(part);
		}

		if (parts.size() >= 6) { // Keep entries with 5 or more spaces
			FileEntry entry;
			entry.Type = (parts[0][0] == 'd') ? "FOLDER" : "FILE";

			if (entry.Type == "FOLDER") {
				entry.Size = -1;
				entry.DateTime = parts[3] + " " + parts[4];
				entry.Name = "";
				for (int j = 5; j < parts.size(); ++j) {
					entry.Name += parts[j] + (j < parts.size() - 1 ? " " : "");
				}
			} else {
				entry.Size = std::stoll(parts[3]);
				entry.FormattedSize = formatFileSize(entry.Size);
				entry.DateTime = parts[4] + " " + parts[5];
				entry.Name = "";
				for (int j = 6; j < parts.size(); ++j) {
					entry.Name += parts[j] + (j < parts.size() - 1 ? " " : "");
				}
				entry.Type = DefineFileType(entry.Name);
			}

			fileEntries.push_back(entry);
		}
	}

	return fileEntries;
}

HICON get_icon_for_file(const char* filename, const char* ItemType)
{
	char regPath[MAX_PATH], iconPath[MAX_PATH] = "";
	DWORD size = sizeof(iconPath);
	HKEY hKey;
	HICON hIcon = NULL;
	const char* dot = strrchr(filename, '.');

	if (_stricmp(ItemType, "folder") == 0) {
		// Folder icon
		if (RegOpenKeyExA(HKEY_CLASSES_ROOT, "Folder\\DefaultIcon", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
			RegQueryValueExA(hKey, NULL, NULL, NULL, (LPBYTE)iconPath, &size);
			RegCloseKey(hKey);
		}
	} else if (dot) {
		// Try .ext -> class -> DefaultIcon
		char className[128] = "";
		DWORD classSize = sizeof(className);
		snprintf(regPath, sizeof(regPath), "%s", dot);
		if (RegOpenKeyExA(HKEY_CLASSES_ROOT, regPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
			RegQueryValueExA(hKey, NULL, NULL, NULL, (LPBYTE)className, &classSize);
			RegCloseKey(hKey);

			if (className[0]) {
				snprintf(regPath, sizeof(regPath), "%s\\DefaultIcon", className);
				size = sizeof(iconPath);
				if (RegOpenKeyExA(HKEY_CLASSES_ROOT, regPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
					RegQueryValueExA(hKey, NULL, NULL, NULL, (LPBYTE)iconPath, &size);
					RegCloseKey(hKey);
				}
			}
		}
	}

	// Extract icon
	if (iconPath[0]) {
		char iconFile[MAX_PATH];
		int index = 0;
		char* comma = strrchr(iconPath, ',');
		if (comma) {
			*comma = '\0';
			index = atoi(comma + 1);
		}
		strcpy(iconFile, iconPath);
		hIcon = ExtractIconA(NULL, iconFile, index);
	}

	// Fallback generic file/folder icon
	if (!hIcon || (UINT_PTR)hIcon <= 1) {
		SHFILEINFOA sfi = {0};
		UINT flags = SHGFI_ICON | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES;
		DWORD attrs = (_stricmp(ItemType, "folder") == 0) ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
		SHGetFileInfoA(filename, attrs, &sfi, sizeof(sfi), flags);
		hIcon = sfi.hIcon;
	}

	return hIcon;
}

void PopulateListView(void)
{
	ListView_DeleteAllItems(hListView1); // Clear existing rows

	g_checked.resize(entries.size(), false);

	for (int i = 0; i < entries.size(); ++i) {

		LVITEM item = { 0 };
		item.mask = LVIF_TEXT;
		item.iItem = i;
		item.iSubItem = 0;
		item.pszText = (LPSTR)""; // Empty checkbox column
		ListView_InsertItem(hListView1, &item);
	}
}

void DrawListViewCell(HDC hdc, RECT rc, int row, int col, bool selected, bool reverse)
{
	const FileEntry& f = entries[row];
	char buf[128];
	SetBkMode(hdc, TRANSPARENT);

	int fontSize = 10;
	HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
	LOGFONT lf;
	GetObject(hFont, sizeof(LOGFONT), &lf);
	//if(FontExists("Segoe UI")) { strcpy(lf.lfFaceName, "Segoe UI"); }

	lf.lfHeight = -MulDiv(fontSize, GetDeviceCaps(hdc, LOGPIXELSY), 72);

	if (row == g_hoveredRow && SW1usctoiCB1 && col == 2) {
		lf.lfUnderline = TRUE;
	}

	HFONT hNewFont = CreateFontIndirect(&lf);
	HFONT hOldFont = (HFONT)SelectObject(hdc, hNewFont);

	if (row == g_hoveredRow && SW1usctoiCB1 && col == 2) {
		SetTextColor(hdc, RGB(0, 0, 255)); // Blue color
	} else {
		SetTextColor(hdc, selected ? RGB(255, 255, 255) : RGB(0, 0, 0));
	}

	switch (col) {
	case 0: {
		RECT cb = { rc.left + 7, rc.top + 4, rc.left + 19, rc.top + 22 };
		DrawFrameControl(hdc, &cb, DFC_BUTTON, DFCS_BUTTONCHECK | (g_checked[row] ? DFCS_CHECKED : 0));
		break;
	}
	case 1:
		if (reverse) sprintf(buf, "%d", entries.size() - row);
		else sprintf(buf, "%d", row + 1);
		DrawTextA(hdc, buf, strlen(buf), &rc, DT_SINGLELINE | DT_CENTER | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
		break;
	case 2: {
		HICON hIcon = get_icon_for_file(f.Name.c_str(), (f.Type == "FOLDER") ? "FOLDER" : "FILE");
		DrawIconEx(hdc, rc.left + 6, rc.top + 4, hIcon, 16, 16, 0, NULL, DI_NORMAL);
		DestroyIcon(hIcon);
		int textX = rc.left + 25;
		RECT textRect = rc;
		textRect.left = textX;
		if (row == g_hoveredRow) {
			RECT hoverRect = rc;
			hoverRect.left = textX - 2;
			hoverRect.top += 1;
			hoverRect.bottom -= 1;
			hoverRect.right -= 4;
			HBRUSH hoverBrush = CreateSolidBrush(RGB(229, 243, 255));
			HPEN hoverPen = CreatePen(PS_SOLID, 1, RGB(153, 209, 255));
			HGDIOBJ oldBrush = SelectObject(hdc, hoverBrush);
			HGDIOBJ oldPen = SelectObject(hdc, hoverPen);
			RoundRect(hdc, hoverRect.left, hoverRect.top, hoverRect.right, hoverRect.bottom, 6, 6);
			SelectObject(hdc, oldBrush);
			SelectObject(hdc, oldPen);
			DeleteObject(hoverBrush);
			DeleteObject(hoverPen);
		}
		DrawTextA(hdc, f.Name.c_str(), f.Name.length(), &textRect, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
		break;
	}
	case 3: {
		const char* type = (f.Type == "FOLDER") ? "FOLDER" : "FILE";
		if (f.Type != "FOLDER") type = f.Type.c_str(); // type = DefineFileType(f.Name).c_str();
		DrawTextA(hdc, type, strlen(type), &rc, DT_SINGLELINE | DT_VCENTER | DT_RIGHT | DT_END_ELLIPSIS | DT_NOPREFIX);
		break;
	}
	case 4: {
		if (f.Type == "FOLDER") strcpy(buf, "-");
		else strcpy(buf, f.FormattedSize.c_str());
		// Right-align
		DrawTextA(hdc, buf, strlen(buf), &rc, DT_SINGLELINE | DT_VCENTER | DT_RIGHT | DT_END_ELLIPSIS | DT_NOPREFIX);
		break;
	}
	case 5:
		DrawTextA(hdc, f.DateTime.c_str(), f.DateTime.length(), &rc, DT_SINGLELINE | DT_VCENTER | DT_RIGHT | DT_END_ELLIPSIS | DT_NOPREFIX);
		break;
	}

	SelectObject(hdc, hOldFont);
	DeleteObject(hNewFont);
}

bool IsAnyCheckboxChecked()
{
	return std::any_of(g_checked.begin(), g_checked.end(), [](bool c) {
		return c;
	});
}

bool IsPointInCheckbox(HWND hwnd, int row, POINT pt)
{
	RECT rc;
	ListView_GetSubItemRect(hwnd, row, 0, LVIR_BOUNDS, &rc);
	RECT checkboxRect = { rc.left + 7, rc.top + 4, rc.left + 19, rc.top + 16 };
	return PtInRect(&checkboxRect, pt);
}

void ToggleCheckbox(HWND hwnd, int row)
{
	g_checked[row] = !g_checked[row];
	RECT rc;
	ListView_GetItemRect(hwnd, row, &rc, LVIR_BOUNDS);
	InvalidateRect(hwnd, &rc, TRUE);

	if (IsAnyCheckboxChecked()) {
		EnableItemButtons1();
		ClearNormalSelection(hwnd);
	} else {
		DisableItemButtons1();
	}

	if (g_checked[row]) {
		selectedItems.push_back(LS_PATH + entries[row].Name);
	} else {
		// Remove from selectedItems if unchecked
		selectedItems.erase(std::remove(selectedItems.begin(), selectedItems.end(), LS_PATH + entries[row].Name), selectedItems.end());
	}

	UpdateStatusBarSelection();

}

void ClearNormalSelection(HWND hwnd)
{
	if (g_selectedRow != -1) {
		RECT rc;
		ListView_GetItemRect(hwnd, g_selectedRow, &rc, LVIR_BOUNDS);
		g_selectedRow = -1;
		InvalidateRect(hwnd, &rc, TRUE);
	}
}

void HandleNormalClickSelection(HWND hwnd, int row)
{
	if (g_selectedRow == row) {
		// Unselect if clicked again
		DisableItemButtons1();
		if (LS_PATH == "/sdcard/") {
			EnableWindow(hBtnUp1, FALSE);
		} else {
			EnableWindow(hBtnUp1, TRUE);
		}
		ClearNormalSelection(hwnd);
	} else {
		EnableItemButtons1();
		int oldRow = g_selectedRow;
		g_selectedRow = row;

		if (oldRow >= 0) {
			RECT oldRc;
			ListView_GetItemRect(hwnd, oldRow, &oldRc, LVIR_BOUNDS);
			InvalidateRect(hwnd, &oldRc, TRUE);
		}

		RECT newRc;
		ListView_GetItemRect(hwnd, row, &newRc, LVIR_BOUNDS);
		InvalidateRect(hwnd, &newRc, TRUE);
	}

	if (g_selectedRow != -1) {
		selectedItems.clear(); // Clear previous selection
		selectedItems.push_back(LS_PATH + entries[g_selectedRow].Name);
	}

	UpdateStatusBarSelection();
}

void UpdateHoveredRow(HWND hListView, POINT pt)
{
	LVHITTESTINFO hit = { 0 };
	hit.pt = pt;
	int item = ListView_HitTest(hListView, &hit);

	int newHovered = -1;

	if (item >= 0 && (hit.flags & LVHT_ONITEM)) {
		LVHITTESTINFO subHit = { 0 };
		subHit.pt = pt;
		ListView_SubItemHitTest(hListView, &subHit);

		if (subHit.iSubItem == 2) {
			// Only hover if item is NOT selected or checked
			if (item != g_selectedRow && !g_checked[item]) {
				newHovered = item;
			}
		}
	}

	if (newHovered != g_hoveredRow) {
		int old = g_hoveredRow;
		g_hoveredRow = newHovered;

		if (old >= 0) {
			RECT rc;
			ListView_GetItemRect(hListView, old, &rc, LVIR_BOUNDS);
			InvalidateRect(hListView, &rc, FALSE);
		}
		if (g_hoveredRow >= 0) {
			RECT rc;
			ListView_GetItemRect(hListView, g_hoveredRow, &rc, LVIR_BOUNDS);
			InvalidateRect(hListView, &rc, FALSE);
		}
	}
}

void ClearHoveredRowIfSelectedOrChecked(HWND hwnd)
{
	if (g_hoveredRow != -1) {
		if (g_hoveredRow == g_selectedRow || g_checked[g_hoveredRow]) {
			RECT rc;
			ListView_GetItemRect(hwnd, g_hoveredRow, &rc, LVIR_BOUNDS);
			InvalidateRect(hwnd, &rc, FALSE);
			g_hoveredRow = -1;
		}
	}
}

void SortFileEntries(void)
{
	if (LV1_LastSortColumn > 1 && LV1_LastSortColumn < 6) {
		LV1_SortAscending = !LV1_SortAscending;
	}

	if (LV1_LastSortColumn == 0) {
		bool allChecked = std::all_of(g_checked.begin(), g_checked.end(), [](bool c) {
			return c;
		});
		for (int i = 0; i < g_checked.size(); ++i) {
			g_checked[i] = !allChecked;
		}
		PopulateListView();
		UpdateStatusBarSelection();
	} else if (LV1_LastSortColumn == 1) {
		std::reverse(entries.begin(), entries.end());
		reverse_list = !reverse_list;
		LV1_SortAscending = !LV1_SortAscending;
	} else {
		std::sort(entries.begin(), entries.end(), [](const FileEntry& a, const FileEntry& b) {
			int cmp = 0;
			switch (LV1_LastSortColumn) {
			case 2: // Name
				cmp = _stricmp(a.Name.c_str(), b.Name.c_str());
				break;
			case 3: // Type
				cmp = _stricmp(a.Type.c_str(), b.Type.c_str());
				break;
			case 4: // Size
				cmp = (a.Size < b.Size) ? -1 : (a.Size > b.Size) ? 1 : 0;
				break;
			case 5: // DateTime
				cmp = _stricmp(a.DateTime.c_str(), b.DateTime.c_str());
				break;
			}
			return LV1_SortAscending ? cmp < 0 : cmp > 0;
		});
	}
	PopulateListView();
	SetSortArrow();
}

void SetSortArrow(void)
{
	HWND hHeader = ListView_GetHeader(hListView1);
	int columnCount = Header_GetItemCount(hHeader);
	for (int i = 1; i < 6; i++) {
		HDITEM hdi = {0};
		hdi.mask = HDI_FORMAT;
		if (Header_GetItem(hHeader, i, &hdi)) {
			// Clear previous arrows
			hdi.fmt &= ~(HDF_SORTUP | HDF_SORTDOWN);
			// Set arrow on the sorted column
			if (i == LV1_LastSortColumn) {
				hdi.fmt |= (LV1_SortAscending ? HDF_SORTUP : HDF_SORTDOWN);
			}
			Header_SetItem(hHeader, i, &hdi);
		}
	}
}

HICON LoadShellIcon(LPCSTR dllName, int index, int size)
{
	HICON hIcon = NULL;
	ExtractIconExA(dllName, index, NULL, &hIcon, 1);
	if (hIcon && size != 32) {
		hIcon = (HICON)CopyImage(hIcon, IMAGE_ICON, size, size, LR_COPYFROMRESOURCE);
	}
	return hIcon;
}

std::string GetSDParentDir(const std::string& path)
{
	if (path.empty()) return "";
	if (path == "/sdcard/" || path == "/sdcard" || path == "sdcard/") return "/sdcard/";
	std::string trimmed = path;
	if (trimmed.back() == '/' || trimmed.back() == '\\') {
		trimmed.pop_back();
	}
	size_t lastSlash = trimmed.find_last_of("/\\");
	if (lastSlash == std::string::npos) return "/";
	std::string parent = trimmed.substr(0, lastSlash + 1);
	// Prevent going above /sdcard/
	if (parent.length() < 9) return "/sdcard/";
	return parent;
}

void ReplaceChars(std::string& str, const std::string& find, const std::string& replace)
{
	size_t pos = 0;
	while ((pos = str.find(find, pos)) != std::string::npos)
		str.replace(pos, find.length(), replace);
}

std::string GetExeFolder(void)
{
	char path[MAX_PATH];
	GetModuleFileName(NULL, path, MAX_PATH);
	std::string fullPath(path);
	return fullPath.substr(0, fullPath.find_last_of("\\/") + 1);
}

std::string GetexePath(void)
{
	char path[MAX_PATH];
	GetModuleFileName(NULL, path, MAX_PATH);
	return std::string(path);
}

std::string GetexeDataFolder(void) {
	char exePath[MAX_PATH];
	GetModuleFileName(NULL, exePath, MAX_PATH);
	std::string exeName = strrchr(exePath, '\\') + 1;
	ReplaceChars(exeName, ".", "_");
	ReplaceChars(exeName, " ", "_");
    std::string exeDataDIR = GetExeFolder() + exeName + "\\";
	return exeDataDIR;
}

std::string GetFileNameFromPath(const std::string& androidPath)
{
	size_t pos = androidPath.find_last_of("/\\");
	return (pos != std::string::npos) ? androidPath.substr(pos + 1) : androidPath;
}

std::string GetFileExtension(const std::string& fileName)
{
	size_t pos = fileName.find_last_of(".");
	if (pos != std::string::npos) {
		std::string ext = fileName.substr(pos + 1);
		for (char& c : ext) {
			c = std::tolower(c);
		}
		return ext;
	}
	return "";
}

void ReWriteLineBreaksByExtension(const std::string& filePath)
{
	if(!SW1rwlbCB1) {
		return;
	}
	std::string extension = filePath.substr(filePath.find_last_of(".") + 1);
	std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
	const char* validExtensions[] = {"txt", "js", "css", "php", "lua", "cpp", "c", "ahk", "vbs", "json", "htm", "html", "cgi", ".htaccess"};
	bool isValidExtension = false;
	for (const auto& ext : validExtensions) {
		if (extension == ext) {
			isValidExtension = true;
			break;
		}
	}
	if (isValidExtension) {
		HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile != INVALID_HANDLE_VALUE) {
			DWORD fileSize = GetFileSize(hFile, NULL);
			if (fileSize != INVALID_FILE_SIZE) {
				char* buffer = new char[fileSize];
				DWORD bytesRead;
				if (ReadFile(hFile, buffer, fileSize, &bytesRead, NULL)) {
					CloseHandle(hFile);

					std::string contents(buffer, fileSize);
					delete[] buffer;

					if (contents.find("\r\n") == std::string::npos && contents.find('\r') == std::string::npos) {
						// Only \n line breaks, replace with \r\n
						size_t pos = 0;
						while ((pos = contents.find('\n', pos)) != std::string::npos) {
							contents.replace(pos, 1, "\r\n");
							pos += 2;
						}

						hFile = CreateFileA(filePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
						if (hFile != INVALID_HANDLE_VALUE) {
							DWORD bytesWritten;
							WriteFile(hFile, contents.c_str(), contents.size(), &bytesWritten, NULL);
							CloseHandle(hFile);
						}
					}
				} else {
					CloseHandle(hFile);
				}
			} else {
				CloseHandle(hFile);
			}
		}
	}
}

std::string GetProgramDir(unsigned int PDID)
{

	//GetProgramDir(0) = exe Data Folder
	//GetProgramDir(1) = LOGS
	//GetProgramDir(2) = DOWNLOADS
	//GetProgramDir(3) = OPENEDFILES

	// Get exe path and name
	char exePath[MAX_PATH];
	GetModuleFileName(NULL, exePath, MAX_PATH);
	std::string exeName = strrchr(exePath, '\\') + 1;
	ReplaceChars(exeName, ".", "_");
	ReplaceChars(exeName, " ", "_");

	// Create EXE Working Directory
	std::string exeWorkingDir = GetExeFolder() + exeName;
	_mkdir(exeWorkingDir.c_str());
	
	if (PDID == 0) {
		return exeWorkingDir + "\\";
	}
	else if (PDID == 1) {
		// Create Logs Directory
		std::string LogsFolder = exeWorkingDir + "\\logs";
		_mkdir(LogsFolder.c_str());
		return LogsFolder;
	} else if (PDID == 2) {
		// Create Downloads Directory
		std::string DownloadsFolder = exeWorkingDir + "\\DOWNLOADS";
		_mkdir(DownloadsFolder.c_str());
		return DownloadsFolder;
	} else {
		// Create TEMP OPENEDFILES folder
		std::string tempPath = exeWorkingDir + "\\TEMP";;
		_mkdir(tempPath.c_str());
		tempPath = tempPath + "\\OPENEDFILES\\";
		_mkdir(tempPath.c_str());
		// Create date folder
		time_t now = time(0);
		tm* ltm = localtime(&now);
		char dateStr[16];
		sprintf(dateStr, "%04d-%02d-%02d", 1900 + ltm->tm_year, 1 + ltm->tm_mon, ltm->tm_mday);
		std::string dateFolder = tempPath + dateStr + "\\";
		_mkdir(dateFolder.c_str());
		return dateFolder;
	}
}

void RunCommandAsync(const std::string& cmd, bool HideProcess, std::string ExplorerDirOpenAfter) {
    std::thread([cmd, HideProcess, ExplorerDirOpenAfter]() {
        PROCESS_INFORMATION pi1 = { 0 };
        STARTUPINFOA si1 = { 0 };
        si1.cb = sizeof(si1);
        si1.dwFlags |= STARTF_USESHOWWINDOW;
        si1.wShowWindow = HideProcess ? SW_HIDE : SW_SHOW;
        DWORD creationFlags = HideProcess ? CREATE_NO_WINDOW : 0;
        std::vector<char> cmdBuffer(cmd.begin(), cmd.end());
        cmdBuffer.push_back('\0');
        if (!CreateProcessA(NULL, cmdBuffer.data(), NULL, NULL, FALSE, creationFlags, NULL, NULL, &si1, &pi1)) {
            return;
        }
        CloseHandle(pi1.hThread);
        WaitForSingleObject(pi1.hProcess, 86400000);
        CloseHandle(pi1.hProcess);
        if (!ExplorerDirOpenAfter.empty()) {
			if(ExplorerDirOpenAfter == "refresh")
			{ PRELOADFL(); return; }
            PROCESS_INFORMATION pi2 = { 0 };
            STARTUPINFOA si2 = { 0 };
            si2.cb = sizeof(si2);
            si2.dwFlags |= STARTF_USESHOWWINDOW;
            si2.wShowWindow = SW_SHOW;
            std::string RunWithExplorerCMD = "explorer \"" + ExplorerDirOpenAfter + "\"";
            std::vector<char> cmdBuffer2(RunWithExplorerCMD.begin(), RunWithExplorerCMD.end());
            cmdBuffer2.push_back('\0');
            if (!CreateProcessA(NULL, cmdBuffer2.data(), NULL, NULL, FALSE, 0, NULL, NULL, &si2, &pi2)) {
                return;
            }
            CloseHandle(pi2.hThread);
            WaitForSingleObject(pi2.hProcess, 3000);
            CloseHandle(pi2.hProcess);
        }
    }).detach();
}

void MoveWithoutErase(const std::string& path)
{
if (path.find("/.adbfetemp") != std::string::npos) {
return;
}
LOG_THIS("[ void MoveWithoutErase(.) ] Attempting to backup \"" + path + "\" before DELETION...\r\n");
std::thread([path]() {
std::string deletedFilesFolder = GetProgramDir(0) + "DELETEDFILESFOLDER\\";
SHCreateDirectoryEx(NULL, deletedFilesFolder.c_str(), NULL);

std::string commands[] = {
    adbPath + " shell mv \"" + escapeShellChars(path) + "\" /sdcard/.adbfetemp/"
    ,adbPath + " pull -a -p \"/sdcard/.adbfetemp/" + GetFileNameFromPath(path) + "\" " + deletedFilesFolder
    ,adbPath + " shell rm -rf \"" + escapeShellChars("/sdcard/.adbfetemp/" + GetFileNameFromPath(path)) + "\""
};
bool HideProcess2 = true;
PROCESS_INFORMATION pi = { 0 };
STARTUPINFOA si = { 0 };
si.cb = sizeof(si);
si.dwFlags |= STARTF_USESHOWWINDOW;
si.wShowWindow = HideProcess2 ? SW_HIDE : SW_SHOW;
DWORD creationFlags = HideProcess2 ? CREATE_NO_WINDOW : 0;
int rhcd = 1;
for (const auto& cmd : commands) {
    std::vector<char> cmdBuffer(cmd.begin(), cmd.end());
    cmdBuffer.push_back('\0');
    if (!CreateProcessA(NULL, cmdBuffer.data(), NULL, NULL, FALSE, creationFlags, NULL, NULL, &si, &pi)) {
        // Handle error
        return;
    }
    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess, 3600000);
    CloseHandle(pi.hProcess);
	if (rhcd == 1)
	{
	std::string currentFL = getADBOutput();
	entries = parseFileList(currentFL);
	PopulateListView();
	}
	rhcd++;
}
}).detach();
}

bool IsWindowTopMost(HWND hWnd) {
    return (GetWindowLong(hWnd, GWL_EXSTYLE) & WS_EX_TOPMOST) != 0;
}

std::string FindCopyOfFile(std::string filename, long long SizeInBytes) {

    std::string DIR1 = GetProgramDir(2);
    std::string DIR2 = GetProgramDir(3);

	struct FileInfo {
		std::string Name;
		std::string Path;
		long long Size;
		FILETIME DateModified;
	};

    std::vector<FileInfo> files;

    // Gather files from DIR1
    WIN32_FIND_DATA findData;
    HANDLE hFind = FindFirstFileA((DIR1 + "*").c_str(), &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                FileInfo file;
                file.Name = findData.cFileName;
                file.Path = DIR1 + findData.cFileName;
                file.Size = (static_cast<long long>(findData.nFileSizeHigh) << 32) | findData.nFileSizeLow;
                file.DateModified = findData.ftLastWriteTime;
                files.push_back(file);
            }
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    }

    // Gather files from DIR2
    hFind = FindFirstFileA((DIR2 + "*").c_str(), &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                FileInfo file;
                file.Name = findData.cFileName;
                file.Path = DIR2 + findData.cFileName;
                file.Size = (static_cast<long long>(findData.nFileSizeHigh) << 32) | findData.nFileSizeLow;
                file.DateModified = findData.ftLastWriteTime;
                files.push_back(file);
            }
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    }

    // Find most recent file with matching name
    FileInfo* mostRecentFile = nullptr;
    for (auto& file : files) {
        if (file.Name == filename) {
            if (!mostRecentFile || CompareFileTime(&file.DateModified, &mostRecentFile->DateModified) > 0) {
                mostRecentFile = &file;
            }
        }
    }

    if (mostRecentFile) {
        SYSTEMTIME st;
        FileTimeToSystemTime(&mostRecentFile->DateModified, &st);
        char dateStr[64];
        sprintf(dateStr, "%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        //MessageBox(NULL, ("Found file: " + mostRecentFile->Path + "\nSize: " + std::to_string(mostRecentFile->Size) + " bytes\nDate Modified: " + dateStr).c_str(), APP_TITLE2, MB_OK);
        return mostRecentFile->Path;
    }

    return "";
}

void OpenItem(const std::string& androidPath, const std::string& Type, long long SizeInBytes)
{
	EnableWindow(hBtnOpen1, FALSE);
	EnableWindow(hBtnDelete1, FALSE);
	ShowWindow(hListViewStatus1, SW_HIDE);
	ClearNormalSelection(hListView1);
	ClearHoveredRowIfSelectedOrChecked(hListView1);

	if (Type == "FOLDER") {
		LS_PATH = androidPath + "/";
		std::string currentFL = getADBOutput();
		entries = parseFileList(currentFL);
		PopulateListView();
		if (currentFL.empty()) {
			ShowWindow(hListViewStatus1, SW_SHOW);
		} else {
			EnableWindow(hBtnOpen1, TRUE);
		}
		status_text2 = "Current Path: " + LS_PATH;
		SendMessage(hStatusBar1, SB_SETTEXT, 1, (LPARAM)status_text2.c_str());
		std::string wTitle = "ADB File Explorer: " + LS_PATH;
		SetWindowText(hListViewWindow1, wTitle.c_str());
		if (LS_PATH == "/sdcard/") {
			EnableWindow(hBtnUp1, FALSE);
		} else {
			EnableWindow(hBtnUp1, TRUE);
		}
		return;
	}

	std::string dateFolder = GetProgramDir(3);

	// Pull file if ADBconnected
	std::string fileName = GetFileNameFromPath(androidPath);
	std::string localFilePath, pullCmd;
	int result;
	
	if(!ADBconnected && SW1cbpCB1)
	{
		localFilePath = FindCopyOfFile(fileName, SizeInBytes);
		if(localFilePath.empty())
		{ MessageBox(NULL, "Android Debug Bridge is Offline!\nCannot Open or Find File.", APP_TITLE2, MB_OK | MB_ICONERROR); return; }
		result = 0;
	}
	else
	{
		localFilePath = dateFolder + fileName;
		pullCmd = adbPath + " pull -p \"" + androidPath + "\" \"" + localFilePath + "\"";
		result = system(pullCmd.c_str());
	}
	
	// Open file if success
	if (result == 0) {
		ReWriteLineBreaksByExtension(localFilePath);
		std::string RunWithExplorerCMD = "explorer \"" + localFilePath + "\"";
		system(RunWithExplorerCMD.c_str());
	}
}

void DisableItemButtons1(void)
{
	if (LS_PATH == "/sdcard/") {
		EnableWindow(hBtnUp1, FALSE);
	} else {
		EnableWindow(hBtnUp1, TRUE);
	}
	EnableWindow(hBtnUp1, FALSE);
	EnableWindow(hBtnOpen1, FALSE);
	EnableWindow(hBtnDelete1, FALSE);
}

void EnableItemButtons1(void)
{
	if (LS_PATH == "/sdcard/") {
		EnableWindow(hBtnUp1, FALSE);
	} else {
		EnableWindow(hBtnUp1, TRUE);
	}
	EnableWindow(hBtnOpen1, TRUE);
	EnableWindow(hBtnDelete1, TRUE);
}

std::string formatFileSize(long long SizeInBytes)
{
	const char* units[] = {"B", "KB", "MB", "GB"};
	int index = 0;
	double sizeDouble = SizeInBytes;
	while (sizeDouble >= 1024 && index < 3) {
		sizeDouble /= 1024;
		index++;
	}
	char buffer[20];
	sprintf(buffer, "%.2f %s", sizeDouble, units[index]);
	return buffer;
}

std::string DefineFileType(const std::string& File)
{
	size_t dotPos = File.find_last_of('.');
	if (dotPos == std::string::npos) {
		return "FILE";
	}
	std::string ext = File.substr(dotPos + 1);
	if (ext.length() > 5) {
		return "FILE";
	}
	for (char& c : ext) {
		c = std::toupper(c);
	}
	return ext;
}

std::vector<int> GetSelectedIndices(void)
{
	std::vector<int> selectedIndices;
	for (int i = 0; i < g_checked.size(); ++i) {
		if (g_checked[i]) {
			selectedIndices.push_back(i);
		}
	}
	if (g_selectedRow != -1 && std::find(selectedIndices.begin(), selectedIndices.end(), g_selectedRow) == selectedIndices.end()) {
		selectedIndices.push_back(g_selectedRow);
	}
	return selectedIndices;
}

std::pair<std::vector<std::string>, std::vector<std::string>> GetSelectedPathsAndTypes(void)
{
	std::vector<int> indices = GetSelectedIndices();
	std::vector<std::string> paths;
	std::vector<std::string> types;

	for (int index : indices) {
		paths.push_back(LS_PATH + entries[index].Name);
		types.push_back(entries[index].Type);
	}

	if (paths.empty()) {
		paths.push_back(LS_PATH);
		types.push_back("FOLDER");
	}

	return {paths, types};
}

void UpdateStatusBarSelection(void)
{
	std::vector<int> indices = GetSelectedIndices();

	if (indices.empty()) {
		status_text3 = "Items Selected: None.";
	} else {
		std::string selectedPaths;
		for (int i = 0; i < indices.size(); ++i) {
			if (i > 0) {
				selectedPaths += ", ";
			}
			selectedPaths += LS_PATH + entries[indices[i]].Name;
		}
		std::string countText = (indices.size() == 1) ? "Item Selected: " : "Items Selected: ";
		countText += "(" + std::to_string(indices.size()) + ") ";
		if (countText.length() + selectedPaths.length() > maxDisplayChars) {
			int remainingChars = maxDisplayChars - countText.length() - 3; // 3 for ellipsis
			if (remainingChars < 0) remainingChars = 0;
			selectedPaths = selectedPaths.substr(0, remainingChars) + "...";
		}
		status_text3 = countText + selectedPaths + ".";
	}
	SendMessage(hStatusBar1, SB_SETTEXT, 2, (LPARAM)status_text3.c_str());
	EnableWindow(hBtnOpen1, indices.size() == 1);
}

std::string BrowseForFile()
{
	OPENFILENAME ofn;
	char szFile[260];
	ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = NULL;
	ofn.lpstrFile = szFile;
	ofn.lpstrFile[0] = '\0';
	ofn.nMaxFile = sizeof(szFile);
	ofn.lpstrFilter = "All Files\0*.*\0";
	ofn.nFilterIndex = 1;
	ofn.lpstrFileTitle = NULL;
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = NULL;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

	if (GetOpenFileName(&ofn) == TRUE) {
		return ofn.lpstrFile;
	} else {
		return "";
	}
}

std::string BrowseForFolder(void)
{
	BROWSEINFO bi = {0};
	bi.hwndOwner = NULL;
	bi.pszDisplayName = 0;
	bi.pidlRoot = NULL;
	bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
	bi.lpfn = NULL;

	LPITEMIDLIST pidl = SHBrowseForFolder(&bi);
	if (pidl != 0) {
		char path[MAX_PATH];
		SHGetPathFromIDList(pidl, path);
		IMalloc* imalloc = 0;
		if (SUCCEEDED(SHGetMalloc(&imalloc))) {
			imalloc->Free(pidl);
			imalloc->Release();
		}
		return path;
	}
	return "";
}

void TryDownloading(void)
{

	auto [paths, types] = GetSelectedPathsAndTypes();
	std::string destDir = GetProgramDir(2);

	/*
		destDir = BrowseForFolder();
		if (!destDir.empty()) {
			// User selected a directory, proceed with download
			//MessageBoxA(NULL, destDir.c_str(), "Selected Directory", MB_OK | MB_ICONINFORMATION);
		} else {
			// User cancelled the dialog
			MessageBoxA(NULL, "No directory selected", "Error", MB_OK | MB_ICONERROR);
			return;
		}

		auto [paths, types] = GetSelectedPathsAndTypes();
		std::stringstream ss;
		for (size_t i = 0; i < paths.size(); ++i) {
			ss << paths[i] << " [ " << types[i] << " ]\n";
		}
		MessageBoxA(NULL, ss.str().c_str(), "Selected Paths", MB_OK | MB_ICONINFORMATION);
	*/

	if (paths.size() == 1 && paths[0] == "/sdcard/") {
		if(MessageBoxA(NULL, "Are ya sure you want to download the whole of /sdcard/ ?", "Confirm Root Folder Download", MB_YESNO | MB_ICONINFORMATION) == IDNO) {
			return;
		}
	}

	for (size_t i = 0; i < paths.size(); ++i) {
		std::string pullCmd = adbPath + " pull -a -p \"" + paths[i] + "\" " + destDir;
		RunCommandAsync(pullCmd, false, destDir);
	}

}

void TryUploading(unsigned int itype)
{
	std::string filePath;
	if(itype == 1) {
		filePath = BrowseForFile();
	} else {
		filePath = BrowseForFolder();
	}

	if (!filePath.empty()) {
		std::string pushCmd = adbPath + " push \"" + filePath + "\" \"" + LS_PATH + "\"";
		system(pushCmd.c_str());
		std::string currentFL = getADBOutput();
		entries = parseFileList(currentFL);
		PopulateListView();
	}
}

void TryDeleting(void)
{
	auto [paths, types] = GetSelectedPathsAndTypes();
	if (paths.empty()) {
		MessageBoxA(NULL, "No files selected", "Error", MB_OK | MB_ICONERROR);
		return;
	}

	if (paths.size() == 1 && paths[0] == "/sdcard/" /*|| !ADBconnected*/) {
		MessageBoxA(NULL, "Cannot delete /sdcard/", APP_TITLE2, MB_OK | MB_ICONERROR);
		return;
	}

	std::stringstream ss;
	ss << "Are you sure you want to delete the following files or directories?\n";
	for (size_t i = 0; i < paths.size(); ++i) {
		ss << paths[i] << "\n";
	}

	int result = MessageBoxA(NULL, ss.str().c_str(), "Confirm Deletion", MB_YESNO | MB_ICONWARNING);
	if (result == IDNO) {
		return;
	}

	if(SW1sbofdiCB1)
	{
	std::string mkdirCmd = adbPath + " shell mkdir -p /sdcard/.adbfetemp/";
	system(mkdirCmd.c_str());
	for (size_t i = 0; i < paths.size(); ++i) {
		MoveWithoutErase(paths[i]);
	}
	}
	else
	{
	for (size_t i = 0; i < paths.size(); ++i) {
		std::string deleteCmd = adbPath + " shell rm -rf \"" + escapeShellChars(paths[i]) + "\"";
		RunCommandAsync(deleteCmd,false,"refresh");
	}
	}
	ClearHoveredRowIfSelectedOrChecked(hListView1);
}

void SaveMainWindowSettings(bool sendlog)
{

	if(!AllowSaveMainWindowSettings || !SW1rmwpCB1) {
		if(sendlog) { LOG_THIS("[ void SaveMainWindowSettings() ] Attempting to SaveMainWindowSettings...\r\n"); }
		return;
	}

	HKEY hKey;
	RegCreateKeyEx(HKEY_CURRENT_USER, "Software\\ADBFE\\v1.0.0.0", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);

	WINDOWPLACEMENT wp = { sizeof(WINDOWPLACEMENT) };
	GetWindowPlacement(hListViewWindow1, &wp);

	const char* isMaximized = (wp.showCmd == SW_MAXIMIZE) ? "Yes" : "No";
	RegSetValueEx(hKey, "OnStartUpIsWindowMaximized", 0, REG_SZ, (LPBYTE)isMaximized, strlen(isMaximized) + 1);

	char buffer[10];
	sprintf(buffer, "%d", wp.rcNormalPosition.bottom - wp.rcNormalPosition.top);
	RegSetValueEx(hKey, "OnStartUpHeight", 0, REG_SZ, (LPBYTE)buffer, strlen(buffer) + 1);

	sprintf(buffer, "%d", wp.rcNormalPosition.right - wp.rcNormalPosition.left);
	RegSetValueEx(hKey, "OnStartUpWidth", 0, REG_SZ, (LPBYTE)buffer, strlen(buffer) + 1);

	sprintf(buffer, "%d", wp.rcNormalPosition.left);
	RegSetValueEx(hKey, "OnStartUpLeftCoordinates", 0, REG_SZ, (LPBYTE)buffer, strlen(buffer) + 1);

	sprintf(buffer, "%d", wp.rcNormalPosition.top);
	RegSetValueEx(hKey, "OnStartUpTopCoordinates", 0, REG_SZ, (LPBYTE)buffer, strlen(buffer) + 1);

	RegCloseKey(hKey);

	LOG_THIS("[ void SaveMainWindowSettings() ] RegCloseKey after SaveMainWindowSettings...\r\n");

}

void RestoreMainWindowSettings(void)
{
	HKEY hKey;
	if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\ADBFE\\v1.0.0.0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
		char buffer[10];
		DWORD size = sizeof(buffer);
		int left=-1, top=-1, width=-1, height=-1;
		char isMaximized[4];

		if (RegQueryValueEx(hKey, "OnStartUpLeftCoordinates", NULL, NULL, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
			left = atoi(buffer);
			size = sizeof(buffer);
			if (RegQueryValueEx(hKey, "OnStartUpTopCoordinates", NULL, NULL, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
				top = atoi(buffer);
				size = sizeof(buffer);
				if (RegQueryValueEx(hKey, "OnStartUpWidth", NULL, NULL, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
					width = atoi(buffer);
					size = sizeof(buffer);
					if (RegQueryValueEx(hKey, "OnStartUpHeight", NULL, NULL, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
						height = atoi(buffer);
						SetWindowPos(hListViewWindow1, NULL, left, top, width, height, SWP_NOZORDER | SWP_NOACTIVATE);
					}
				}
			}
		}

		size = sizeof(isMaximized);
		if (RegQueryValueEx(hKey, "OnStartUpIsWindowMaximized", NULL, NULL, (LPBYTE)isMaximized, &size) == ERROR_SUCCESS) {
			if (strcmp(isMaximized, "Yes") == 0) {
				ShowWindow(hListViewWindow1, SW_MAXIMIZE);
			}
			try {
				std::string lt1 = "[ void RestoreMainWindowSettings() ] Left: " + std::to_string(left) + ", Top: " + std::to_string(top) + ", Width: " + std::to_string(width) + ", Height: " + std::to_string(height) + " & Maximized = " + (strcmp(isMaximized, "Yes") == 0 ? "Yes" : "No");
				LOG_THIS(lt1 + "...\r\n");
			} catch(...) {}
		}

		RegCloseKey(hKey);
	}
}

std::string GRSS(const std::string& name, const std::string& defaultValue)
{
	HKEY hKey;
	std::string result;
	if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\ADBFE\\v1.0.0.0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
		char buffer[256];
		DWORD size = sizeof(buffer);
		if (RegQueryValueExA(hKey, name.c_str(), NULL, NULL, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
			buffer[size - 1] = '\0';
			result = buffer;
		}
		RegCloseKey(hKey);
	}
	return result.empty() ? defaultValue : result;
}

void WRSS(const std::string& name, const std::string& value)
{
	HKEY hKey;
	if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\ADBFE\\v1.0.0.0", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
		RegSetValueExA(hKey, name.c_str(), 0, REG_SZ, (LPBYTE)value.c_str(), value.size() + 1);
		RegCloseKey(hKey);
	}
}

void LOG_THIS(std::string content)
{
	if (content.empty() || content.length() < 3 || !EnableLoggingCB1) return;

	char logPath[MAX_PATH];
	sprintf(logPath, "%s\\current_log.txt", GetProgramDir(1).c_str());

	std::string existingContent;

	if (file_exists(logPath)) {
		FILE *file = fopen(logPath, "r");
		fseek(file, 0, SEEK_END);
		long fileSize = ftell(file);
		fseek(file, 0, SEEK_SET);

		if (fileSize > 200 * 1024) {
			char newLogPath[MAX_PATH];
			for (int i = 99; i > 0; i--) {
				sprintf(newLogPath, "%s\\previous_log%d.txt", GetProgramDir(1).c_str(), i);
				char oldLogPath[MAX_PATH];
				sprintf(oldLogPath, "%s\\previous_log%d.txt", GetProgramDir(1).c_str(), i - 1);
				if (file_exists(oldLogPath)) {
					rename(oldLogPath, newLogPath);
				}
			}
			sprintf(newLogPath, "%s\\previous_log1.txt", GetProgramDir(1).c_str());
			rename(logPath, newLogPath);
			fclose(file);
		} else {
			char *buffer = new char[fileSize + 1];
			size_t bytesRead = fread(buffer, 1, fileSize, file);
			buffer[bytesRead] = '\0';
			existingContent = buffer;
			delete[] buffer;
			fclose(file);
			existingContent = std::regex_replace(existingContent, std::regex("\r\n"), "\n");
			existingContent = std::regex_replace(existingContent, std::regex("\n"), "\r\n");
		}
	}

	FILE *file = fopen(logPath, "w");
	if (file) {
		SYSTEMTIME time = {0};
		GetLocalTime(&time);
		fprintf(file, "%04d/%02d/%02d %02d:%02d:%02d.%03d: %s\r\n%s",
		        time.wYear, time.wMonth, time.wDay,
		        time.wHour, time.wMinute, time.wSecond, time.wMilliseconds,
		        content.c_str(), existingContent.c_str());
		fclose(file);
	}
}

bool FontExists(const char* fontName)
{
	HDC hdc = GetDC(NULL);
	LOGFONT lf = {0};
	lf.lfCharSet = DEFAULT_CHARSET;
	strcpy(lf.lfFaceName, fontName);
	HFONT hFont = CreateFontIndirect(&lf);
	if (hFont == NULL) {
		ReleaseDC(NULL, hdc);
		return false;
	}
	HFONT hOldFont = (HFONT)SelectObject(hdc, hFont);
	bool fontExists = GetFontData(hdc, 0, 0, NULL, 0) != GDI_ERROR;
	SelectObject(hdc, hOldFont);
	DeleteObject(hFont);
	ReleaseDC(NULL, hdc);
	return fontExists;
}

void RefreshTheLogView1(void)
{
	char logPath[MAX_PATH];
	snprintf(logPath, MAX_PATH, "%s\\current_log.txt", GetProgramDir(1).c_str());

	if (file_exists(logPath)) {
		FILE *file = fopen(logPath, "r");
		if (file) {
			std::string logContent;
			char buffer[1024];
			while (fgets(buffer, sizeof(buffer), file)) {
				logContent += buffer;
			}
			fclose(file);
			SetWindowText(hLogViewTextEdit1, logContent.c_str());
		} else {
			char errorMsg[256];
			snprintf(errorMsg, 256, "Failed to open log file: %s", logPath);
			SetWindowText(hLogViewTextEdit1, errorMsg);
		}
	} else {
		char errorMsg[256];
		snprintf(errorMsg, 256, "The File \"%s\" does not exist!", logPath);
		SetWindowText(hLogViewTextEdit1, errorMsg);
	}
	SendMessage(hLogViewTextEdit1, EM_SETSEL, 0, 0);
	SendMessage(hLogViewTextEdit1, EM_SCROLLCARET, 0, 0);
}

void DeleteAllLogs1(void)
{
	if (MessageBox(NULL,"Are you sure you want to erase all log files?",APP_TITLE2,MB_YESNO|MB_ICONWARNING)==IDNO)
	{
		return;
	}
	std::string LogsDir = GetProgramDir(1);
	// recursively or simply completely delete LogsDir if it exists...
	if (PathFileExistsA(LogsDir.c_str())) {
		SHFILEOPSTRUCTA fileOp = {0};
		fileOp.wFunc = FO_DELETE;
		std::string from = LogsDir + "\0\0";
		fileOp.pFrom = from.c_str();
		fileOp.fFlags = FOF_SILENT | FOF_NOCONFIRMATION | FOF_NOERRORUI;
		SHFileOperationA(&fileOp);
	}
	bool ELTemp1 = EnableLoggingCB1;
	EnableLoggingCB1 = true;
	LOG_THIS("[ LRESULT CALLBACK DeleteAllLogs1(....) ] Attempting to Delete Log File Directory...\r\n");
	EnableLoggingCB1 = ELTemp1;
}

void PRELOADFL(void)
{
	if (FUNC1Running) return;
	FUNC1Running = true;

	// Check if process is running and get path of running exe
	
	bool isADBrunning = isProcessRunning("adb.exe");
	
	if(isADBrunning && file_exists(exeFROMisProcessRunning)) {
		adbPath = exeFROMisProcessRunning;
	}
	
	// Check default adb.exe path/location

	if (!isADBrunning && file_exists(GetExeFolder() + "adb.exe")) {
		adbPath = GetExeFolder() + "adb.exe";
	} else if (!isADBrunning && file_exists("G:\\scrcpy\\adb.exe")) {
		adbPath = "G:\\scrcpy\\adb.exe";
	}
	
	// Check registry
	
	if (!adbPath.empty()) {
		WRSS("adbPath", adbPath);
	} else {
	std::string adbPath_reg = GRSS("adbPath", "NONE");
	if(adbPath_reg != "NONE" && file_exists(adbPath_reg)) {
		adbPath = adbPath_reg;
	}
	}
	
	if(!adbPath.empty()) {
	LOG_THIS("[ void PRELOADFL() ] adb.exe Found: " + adbPath + " ///\r\n");
	}

	ADBconnected = isADBconnected();
	
	if (adbPath.empty() && !isADBrunning) {
		LOG_THIS("[ void PRELOADFL() ] adb.exe was NOT Found...\r\n");
		int step1 = MessageBoxA(NULL, "The adb.exe was not found and is not in the current directory!\nWould you like to set the adb.exe path/location?", APP_TITLE2, MB_YESNO | MB_ICONERROR);
		if (step1 == IDYES) {
			std::string filePath = BrowseForFile();
			if(!filePath.empty() && GetFileExtension(filePath) == "exe") {
				adbPath = filePath;
				if(!ADBconnected) {
					MessageBoxA(NULL,("This executable does not execute adb -devices properly:\n" + adbPath).c_str(), APP_TITLE2, MB_OK | MB_ICONWARNING);
					LOG_THIS("[ void PRELOADFL() ] WRONG adb.exe selected...\r\n");
				} else {
					LOG_THIS("[ void PRELOADFL() ] VALID adb.exe selected...\r\n");
					WRSS("adbPath", adbPath);
				}
			}
		}
	}

	// Start adb process if it's not running

	if (!adbPath.empty() && !isADBrunning) {
		LOG_THIS("[ void PRELOADFL() ] ADB is not running...\r\n");
		int step2 = MessageBoxA(NULL, "The adb.exe was found but is not running!\nWould you like to start/restart your Android Debug Bridge (adb.exe)?", APP_TITLE2, MB_YESNO | MB_ICONERROR);
		if (step2 == IDYES) {
			ShellExecuteA(NULL, "open", adbPath.c_str(), "start-server", NULL, SW_HIDE);
			Sleep(5000);
			isADBrunning = isProcessRunning("adb.exe");
		}
	}

	// Check if adb.exe is connected to any device or if's offline

	if (!ADBconnected && SW1cbpCB1)
	{
			std::string storedFL = getADBOutput();
			LOG_THIS("[ void PRELOADFL() ] ADB device is not connected, requesting stored file list...\r\n");
			if (!storedFL.empty()) {
				if (storedFL.find("\\\\\\") != std::string::npos) {
					EnableWindow(hBtnOpen1, TRUE);
					entries = parseFileList(storedFL);
					PopulateListView();
				}
			}
	}

	if (isADBrunning) {
		if(!ADBconnected) {
			LOG_THIS("[ void PRELOADFL() ] ADB device is not connected, requesting user to connect device...\r\n");
			MessageBoxA(NULL, "Your Android Debug Bridge is running but is not connected to any device!\nPlease connect or reconnect your device and go to this application MENU > REFRESH...", APP_TITLE2, MB_OK | MB_ICONWARNING);
			adb_status1 = "ADB Device is Disconnected";
			flashStatus = true;
			if (execTimer2) {
				SetTimer(hListViewWindow1, 2, 1000, Timer2Proc);
			}
		} else {
			LOG_THIS("[ void PRELOADFL() ] ADB device connected, requesting contents of /sdcard/...\r\n");
			flashStatus = false;
			adb_status1 = "ADB Device is Connected";
			InvalidateRect(hStatusBar1, NULL, TRUE);
			EnableWindow(hBtnDownload1, TRUE);
			EnableWindow(hBtnUploadFile1, TRUE);
			EnableWindow(hBtnUploadFolder1, TRUE);
			std::string currentFL = getADBOutput();
			if (!currentFL.empty()) {
				if (currentFL.find("\\\\\\") != std::string::npos) {
					EnableWindow(hBtnOpen1, TRUE);
					entries = parseFileList(currentFL);
					PopulateListView();
				}
			}
		}
	}
	FUNC1Running = false;
}

void StartFEWindow(HINSTANCE hInst, int nCmdShow)
{
	// Register window class
	WNDCLASS wc = { 0 };
	wc.lpfnWndProc = hListViewWindow1Proc;
	wc.hInstance = hInst;
	wc.lpszClassName = "ADBFE_CPP_ListViewWindow1";
	//wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
	wc.hCursor = LoadCursor(NULL, IDC_ARROW);

	// Try loading icon safely
	try {
		HICON hIcon = LoadIcon(hInst, MAKEINTRESOURCE(1));
		if (hIcon)
			wc.hIcon = hIcon;
	} catch (...) {
		wc.hIcon = NULL; // fallback to default
	}

	RegisterClass(&wc);

	int width = 700;
	int height = 410;
	int screenX = (GetSystemMetrics(SM_CXSCREEN) - width) / 2;
	int screenY = (GetSystemMetrics(SM_CYSCREEN) - height) / 2;
	std::string WindowMaximized = "No";

	if(SW1rmwpCB1) {
		height = std::stoi(GRSS("OnStartUpHeight", "410"));
		width = std::stoi(GRSS("OnStartUpWidth", "700"));
		screenX = std::stoi(GRSS("OnStartUpLeftCoordinates", std::to_string(screenX)));
		screenY = std::stoi(GRSS("OnStartUpTopCoordinates", std::to_string(screenY)));
		WindowMaximized = GRSS("OnStartUpIsWindowMaximized", "No");
	}

	LOG_THIS("[ void StartFEWindow(..) ] Restored hListViewWindow1 Coordinates (H:" + std::to_string(height) + ",W:" + std::to_string(width) + ",X:" + std::to_string(screenX) + ",Y:" + std::to_string(screenY) + " & MAXIMIZED:" + (WindowMaximized == "Yes" ? "1" : "0") + ")...\r\n");

	hListViewWindow1 = CreateWindow("ADBFE_CPP_ListViewWindow1", "ADB File Explorer",
	                                WS_OVERLAPPEDWINDOW, screenX, screenY, width, height,
	                                nullptr, nullptr, hInst, nullptr);

	hListViewWindow1 = CreateWindow("ADBFE_CPP_ListViewWindow1", "ADB File Explorer", WS_OVERLAPPEDWINDOW | WS_MAXIMIZE, screenX, screenY, width, height, nullptr, nullptr, hInst, nullptr);

	if (hListViewWindow1 != NULL) {
		LOG_THIS("[ void StartFEWindow(..) ] hListViewWindow1 created successfully...\r\n");
	} else {
		LOG_THIS("[ void StartFEWindow(..) ] hListViewWindow1 NOT created successfully...\r\n");
	}

	if (WindowMaximized == "Yes") {
		ShowWindow(hListViewWindow1, SW_MAXIMIZE);
	} else {
		ShowWindow(hListViewWindow1, nCmdShow);
	}
	UpdateWindow(hListViewWindow1);

}

void StartSettingsWindow1(void)
{

	if (IsWindow(hLogViewWindow1)) {
		DestroyWindow(hLogViewWindow1);
	}

	// Exit if settings window already exists and is valid
	if (IsWindow(hSettingsWindow1)) {
		ShowWindow(hSettingsWindow1, SW_RESTORE);
		SetForegroundWindow(hSettingsWindow1); // bring to front if needed
		return;
	}
	
	LOG_THIS("[ void StartSettingsWindow1() ] Starting Settings Window...\r\n");

	std::string adbPath_reg = GRSS("adbPath", "NONE");
	if(adbPath_reg != "NONE" && file_exists(adbPath_reg)) {
		adbPath = adbPath_reg;
	}
	if(GRSS("RestoreMainWindowPosition", "Yes") == "No") {
		SW1rmwpCB1 = false;
	}
	if(GRSS("EscapeADBShellCommand", "Yes") == "No") {
		SW1epciscCB1 = false;
	}
	if(GRSS("RewriteTEXT2WindowLinesBreaks", "Yes") == "No") {
		SW1rwlbCB1 = false;
	}
	if(GRSS("BackUpDeletedItems", "No") == "Yes") {
		SW1sbofdiCB1 = true;
	}
	if(GRSS("CacheFileLists", "Yes") == "No") {
		SW1cbpCB1 = false;
	}
	if(GRSS("UseSingleClickInFileList", "No") == "Yes") {
		SW1usctoiCB1 = true;
	}

	WNDCLASS wc = {0};
	wc.lpfnWndProc = SettingsWindow1Proc;
	wc.hInstance = GetModuleHandle(NULL);
	wc.lpszClassName = "SettingsWindow1Class";
	wc.hbrBackground = (HBRUSH)GetSysColorBrush(COLOR_BTNFACE);
	// Try loading icon safely
	try {
		HICON hIcon = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(1));
		if (hIcon)
			wc.hIcon = hIcon;
	} catch (...) {
		wc.hIcon = NULL; // fallback to default
	}
	RegisterClass(&wc);

	RECT ownerRect;
	GetWindowRect(hListViewWindow1, &ownerRect);
	int x = (ownerRect.right - ownerRect.left - 535) / 2 + ownerRect.left;
	int y = (ownerRect.bottom - ownerRect.top - 305) / 2 + ownerRect.top;

	hSettingsWindow1 = CreateWindowEx(
	                       0, "SettingsWindow1Class", "ADB File Explorer Settings",
	                       WS_VISIBLE | WS_OVERLAPPEDWINDOW & ~(WS_MAXIMIZEBOX | WS_THICKFRAME),
	                       x, y, 535, 305,
	                       hListViewWindow1, NULL, GetModuleHandle(NULL), NULL
	                   );

	// Set window proc
	SetWindowLongPtr(hSettingsWindow1, GWLP_WNDPROC, (LONG_PTR)SettingsWindow1Proc);

	// ADB.exe Path label
	CreateWindowEx(
	    0, "STATIC", "ADB.exe Path:", WS_VISIBLE | WS_CHILD,
	    10, 12, 160, 20, hSettingsWindow1, NULL, GetModuleHandle(NULL), NULL
	);

	// TextBox
	hSettingsWindow1ADBPath1 = CreateWindowEx(
	                               0, "EDIT", adbPath.c_str(), WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
	                               110, 10, 270, 20, hSettingsWindow1, (HMENU)1, GetModuleHandle(NULL), NULL
	                           );

	// Browse button
	hSettingsWindow1BrowseBTN1 = CreateWindowEx(
	                                 0, "BUTTON", "Browse", WS_VISIBLE | WS_CHILD,
	                                 390, 10, 60, 20, hSettingsWindow1, (HMENU)2, GetModuleHandle(NULL), NULL
	                             );

	// Default button
	hSettingsWindow1DefaultBTN1 = CreateWindowEx(
	                                  0, "BUTTON", "Reset", WS_VISIBLE | WS_CHILD,
	                                  458, 10, 60, 20, hSettingsWindow1, (HMENU)3, GetModuleHandle(NULL), NULL
	                              );

	// Divider line
	CreateWindowEx(
	    0, "STATIC", "", WS_VISIBLE | WS_CHILD | SS_ETCHEDHORZ,
	    0, 40, 540, 2, hSettingsWindow1, NULL, GetModuleHandle(NULL), NULL
	);

	// Restore Main Window Position label
	CreateWindowEx(
	    0, "STATIC", "Restore Main Window Position", WS_VISIBLE | WS_CHILD,
	    10, 50, 200, 20, hSettingsWindow1, NULL, GetModuleHandle(NULL), NULL
	);

	// Checkbox
	hSW1rmwpCB1 = CreateWindowEx(
	                  0, "BUTTON", "", WS_VISIBLE | WS_CHILD | BS_CHECKBOX,
	                  219, 49, 20, 20, hSettingsWindow1, (HMENU)4, GetModuleHandle(NULL), NULL
	              );
	if (SW1rmwpCB1) {
		SendMessage(hSW1rmwpCB1, BM_SETCHECK, BST_CHECKED, 0);
	}

	// Divider line
	CreateWindowEx(
	    0, "STATIC", "", WS_VISIBLE | WS_CHILD | SS_ETCHEDHORZ,
	    0, 80, 540, 2, hSettingsWindow1, NULL, GetModuleHandle(NULL), NULL
	);

	// Escape problematic characters in ADB shell command label
	CreateWindowEx(
	    0, "STATIC", "Escape (\\) problematic characters in ADB shell command", WS_VISIBLE | WS_CHILD,
	    10, 90, 420, 20, hSettingsWindow1, NULL, GetModuleHandle(NULL), NULL
	);

	// Checkbox
	hSW1epciscCB1 = CreateWindowEx(
	                    0, "BUTTON", "", WS_VISIBLE | WS_CHILD | BS_CHECKBOX,
	                    387, 89, 20, 20, hSettingsWindow1, (HMENU)5, GetModuleHandle(NULL), NULL
	                );
	if(SW1epciscCB1) {
		SendMessage(hSW1epciscCB1, BM_SETCHECK, BST_CHECKED, 0);
	}

	// Divider line
	CreateWindowEx(
	    0, "STATIC", "", WS_VISIBLE | WS_CHILD | SS_ETCHEDHORZ,
	    0, 120, 540, 2, hSettingsWindow1, NULL, GetModuleHandle(NULL), NULL
	);

	// Re-write line breaks (\n) when opening text format files label
	CreateWindowEx(
	    0, "STATIC", "Re-write line breaks from \\n to \\r\\n when opening text format files", WS_VISIBLE | WS_CHILD,
	    10, 130, 420, 20, hSettingsWindow1, NULL, GetModuleHandle(NULL), NULL
	);

	// Checkbox
	hSW1rwlbCB1 = CreateWindowEx(
	                  0, "BUTTON", "", WS_VISIBLE | WS_CHILD | BS_CHECKBOX,
	                  437, 129, 20, 20, hSettingsWindow1, (HMENU)6, GetModuleHandle(NULL), NULL
	              );
	if (SW1rwlbCB1) {
		SendMessage(hSW1rwlbCB1, BM_SETCHECK, BST_CHECKED, 0);
	}

	// Divider line
	CreateWindowEx(
	    0, "STATIC", "", WS_VISIBLE | WS_CHILD | SS_ETCHEDHORZ,
	    0, 160, 540, 2, hSettingsWindow1, NULL, GetModuleHandle(NULL), NULL
	);

	// Store backup of deleted items for a few days label
	CreateWindowEx(
	    0, "STATIC", "Store backup of deleted items for several days", WS_VISIBLE | WS_CHILD,
	    10, 170, 310, 20, hSettingsWindow1, NULL, GetModuleHandle(NULL), NULL
	);

	// Checkbox
	hSW1sbofdiCB1 = CreateWindowEx(
	                    0, "BUTTON", "", WS_VISIBLE | WS_CHILD | BS_CHECKBOX,
	                    320, 169, 20, 20, hSettingsWindow1, (HMENU)7, GetModuleHandle(NULL), NULL
	                );
	if (SW1sbofdiCB1) {
		SendMessage(hSW1sbofdiCB1, BM_SETCHECK, BST_CHECKED, 0);
	}

	// Divider line
	CreateWindowEx(
	    0, "STATIC", "", WS_VISIBLE | WS_CHILD | SS_ETCHEDHORZ,
	    0, 200, 540, 2, hSettingsWindow1, NULL, GetModuleHandle(NULL), NULL
	);

	// Cache browsed locations for later viewing when ADB is offline
	CreateWindowEx(
	    0, "STATIC", "Store file lists for later viewing when ADB is offline", WS_VISIBLE | WS_CHILD,
	    10, 210, 390, 20, hSettingsWindow1, NULL, GetModuleHandle(NULL), NULL
	);

	// Checkbox
	hSW1cbpCB1 = CreateWindowEx(
	                 0, "BUTTON", "", WS_VISIBLE | WS_CHILD | BS_CHECKBOX,
	                 346, 209, 20, 20, hSettingsWindow1, (HMENU)8, GetModuleHandle(NULL), NULL
	             );
	if(SW1cbpCB1) {
		SendMessage(hSW1cbpCB1, BM_SETCHECK, BST_CHECKED, 0);
	}

	// Divider line
	CreateWindowEx(
	    0, "STATIC", "", WS_VISIBLE | WS_CHILD | SS_ETCHEDHORZ,
	    0, 240, 540, 2, hSettingsWindow1, NULL, GetModuleHandle(NULL), NULL
	);

	// Use single click to open items in list
	CreateWindowEx(
	    0, "STATIC", "Use single click to open items in the list", WS_VISIBLE | WS_CHILD,
	    10, 250, 270, 20, hSettingsWindow1, NULL, GetModuleHandle(NULL), NULL
	);

	// Checkbox
	HWND hSW1usctoiCB1 = CreateWindowEx(
	                         0, "BUTTON", "", WS_VISIBLE | WS_CHILD | BS_CHECKBOX,
	                         278, 249, 20, 20, hSettingsWindow1, (HMENU)9, GetModuleHandle(NULL), NULL
	                     );
	if(SW1usctoiCB1) {
		SendMessage(hSW1usctoiCB1, BM_SETCHECK, BST_CHECKED, 0);
	}

	g_oldSW1rmwpCB1Proc = (WNDPROC)SetWindowLongPtr(hSW1rmwpCB1, GWLP_WNDPROC, (LONG_PTR)SW1rmwpCB1Proc);
	g_oldSW1epciscCB1Proc = (WNDPROC)SetWindowLongPtr(hSW1epciscCB1, GWLP_WNDPROC, (LONG_PTR)SW1epciscCB1Proc);
	g_oldSW1rwlbCB1Proc = (WNDPROC)SetWindowLongPtr(hSW1rwlbCB1, GWLP_WNDPROC, (LONG_PTR)SW1rwlbCB1Proc);
	g_oldSW1sbofdiCB1Proc = (WNDPROC)SetWindowLongPtr(hSW1sbofdiCB1, GWLP_WNDPROC, (LONG_PTR)SW1sbofdiCB1Proc);
	g_oldSW1cbpCB1Proc = (WNDPROC)SetWindowLongPtr(hSW1cbpCB1, GWLP_WNDPROC, (LONG_PTR)hSW1cbpCB1Proc);
	g_oldSW1usctoiCB1Proc = (WNDPROC)SetWindowLongPtr(hSW1usctoiCB1, GWLP_WNDPROC, (LONG_PTR)SW1usctoiCB1Proc);

	ShowWindow(hSettingsWindow1, SW_SHOW);
	UpdateWindow(hSettingsWindow1);
}

void StartLogViewWindow1(void)
{

	if (IsWindow(hSettingsWindow1)) {
		DestroyWindow(hSettingsWindow1);
	}

	// Exit if settings window already exists and is valid
	if (IsWindow(hLogViewWindow1)) {
		ShowWindow(hLogViewWindow1, SW_RESTORE);
		SetForegroundWindow(hLogViewWindow1); // bring to front if needed
		return;
	}
	
	LOG_THIS("[ void StartLogViewWindow1() ] Starting Log View Window...\r\n");
		
	if(GRSS("EnableLogging", "Yes") == "No") {
		EnableLoggingCB1 = false;
	}

	WNDCLASS wc = {0};
	wc.lpfnWndProc = LogViewWindow1Proc;
	wc.hInstance = GetModuleHandle(NULL);
	wc.lpszClassName = "ViewLogWindow1Class";
	wc.hbrBackground = CreateSolidBrush(RGB(197, 197, 226));

	// Try loading icon safely
	try {
		HICON hIcon = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(1));
		if (hIcon)
			wc.hIcon = hIcon;
	} catch (...) {
		wc.hIcon = NULL; // fallback to default
	}
	RegisterClass(&wc);

	RECT ownerRect;
	GetWindowRect(hListViewWindow1, &ownerRect);
	int x = (ownerRect.right - ownerRect.left - 545) / 2 + ownerRect.left;
	int y = (ownerRect.bottom - ownerRect.top - 380) / 2 + ownerRect.top;

	hLogViewWindow1 = CreateWindowEx(
	                      0, "ViewLogWindow1Class", "ADB File Explorer Log View",
	                      WS_VISIBLE | WS_OVERLAPPEDWINDOW & ~(WS_MAXIMIZEBOX | WS_THICKFRAME),
	                      x, y, 545, 380,
	                      hListViewWindow1, NULL, GetModuleHandle(NULL), NULL
	                  );

	// Set window proc
	SetWindowLongPtr(hLogViewWindow1, GWLP_WNDPROC, (LONG_PTR)LogViewWindow1Proc);

	// Create edit control
	hLogViewTextEdit1 = CreateWindowEx(
	                        0, "EDIT", NULL,
	                        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | WS_VSCROLL,
	                        0, 0, 538, 300,
	                        hLogViewWindow1, (HMENU)1, GetModuleHandle(NULL), NULL
	                    );

	std::string tryfonts1 = "Inconsolata";
	if (!FontExists(tryfonts1.c_str())) {
		tryfonts1 = "Consolas";
		if (!FontExists(tryfonts1.c_str())) {
			tryfonts1 = "Tahoma";
		}
	}

	HFONT hFont2 = CreateFont(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, tryfonts1.c_str());
	SendMessage(hLogViewTextEdit1, WM_SETFONT, (WPARAM)hFont2, TRUE);

	// Refresh button
	hRfreshLVButton1 = CreateWindowEx(
	                       0, "BUTTON", "Refresh LogView",
	                       WS_CHILD | WS_VISIBLE,
	                       90, 310, 130, 30,
	                       hLogViewWindow1, (HMENU)2, GetModuleHandle(NULL), NULL
	                   );

	// Create Clear All Logs button
	hCALButton1 = CreateWindowEx(
	                  0, "BUTTON", "Clear All Logs",
	                  WS_CHILD | WS_VISIBLE,
	                  230, 310, 100, 30,
	                  hLogViewWindow1, (HMENU)3, GetModuleHandle(NULL), NULL
	              );

	// Create Enable Logging label and checkbox
	hEnableLoggingLabel1 = CreateWindowEx(
	                           0, "STATIC", "Enable Logging",
	                           WS_CHILD | WS_VISIBLE,
	                           340, 316, 110, 20,
	                           hLogViewWindow1, NULL, GetModuleHandle(NULL), NULL
	                       );

	hEnableLoggingCheckbox1 = CreateWindowEx(
	                              0, "BUTTON", "",
	                              WS_CHILD | WS_VISIBLE | BS_CHECKBOX,
	                              450, 315, 20, 20,
	                              hLogViewWindow1, (HMENU)4, GetModuleHandle(NULL), NULL
	                          );
	if (EnableLoggingCB1) {
		SendMessage(hEnableLoggingCheckbox1, BM_SETCHECK, BST_CHECKED, 0);
	}

	g_oldCheckbox1Proc = (WNDPROC)SetWindowLongPtr(hEnableLoggingCheckbox1, GWLP_WNDPROC, (LONG_PTR)Checkbox1Proc);

	RefreshTheLogView1();

}

int AttemptRefresh = 0;

void CALLBACK Timer1Proc(HWND hwnd, UINT msg, UINT_PTR id, DWORD time)
{
	ADBconnected = isADBconnected();
	
	if(!ADBconnected) {
		adb_status1 = "ADB Device is Disconnected";
		flashStatus = true;
		AttemptRefresh = 1;
	} else {
		flashStatus = false;
		adb_status1 = "ADB Device is Connected";
		if (AttemptRefresh > 0) {
			InvalidateRect(hStatusBar1, NULL, TRUE);
			PRELOADFL(); }
		AttemptRefresh = 0;
		}

	if(!execTimer1) return;
	execTimer1 = false;
	AllowSaveMainWindowSettings = true;
}

void CALLBACK Timer2Proc(HWND hwnd, UINT msg, UINT_PTR id, DWORD time)
{
	if(!execTimer2) return;
	execTimer2 = false;
	/*if (!IsWindowTopMost(hListViewWindow1)) {
		ShowWindow(hListViewWindow1, SW_RESTORE);
		SetForegroundWindow(hListViewWindow1);
	}*/
}

void CALLBACK Timer3Proc(HWND hwnd, UINT msg, UINT_PTR id, DWORD time)
{
	if (flashStatus) {
		flashVisible = !flashVisible;
		InvalidateRect(hStatusBar1, NULL, TRUE);
	}
}

LRESULT CALLBACK hListViewWindow1Proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{

	switch (msg) {
	case WM_CREATE: {

		INITCOMMONCONTROLSEX icex = { sizeof(icex), ICC_LISTVIEW_CLASSES };
		InitCommonControlsEx(&icex);

		// Create menu
		hMenu1 = CreateMenu();
		hFileMenu1 = CreatePopupMenu();
		AppendMenu(hFileMenu1, MF_STRING, 1, "&REFRESH");
		//AppendMenu(hFileMenu1, MF_STRING, 2, "&EXIT");
		AppendMenu(hFileMenu1, MF_STRING, 3, "&ABOUT");
		AppendMenu(hMenu1, MF_STRING | MF_POPUP, (UINT_PTR)hFileMenu1, "&MENU");
		SetMenu(hwnd, hMenu1);
		//SendMessage(hwnd, WM_CHANGEUISTATE, MAKEWPARAM(UIS_CLEAR, UISF_HIDEACCEL), 0);
		SystemParametersInfo(SPI_SETKEYBOARDCUES, 0, (PVOID)TRUE, 0);

		RECT clientRect;
		GetClientRect(hwnd, &clientRect);

		// Create toolbar background (optional container)
		hToolBar1 = CreateWindowEx( 0, "STATIC", "", WS_CHILD | WS_VISIBLE, 0, 0, clientRect.right, 46, hwnd, NULL, GetModuleHandle(NULL), NULL);

		g_oldToolBar1Proc = (WNDPROC)SetWindowLongPtr(hToolBar1, GWLP_WNDPROC, (LONG_PTR)hToolBar1Proc);

		int btnSpacing = 6;
		int btnHeights = 28;
		int btnWidths[] = { 45, 60, 80, 90, 100, 65, 75, 80 };
		int totalBtnWidth = btnWidths[0] + btnWidths[1] + btnWidths[2] + btnWidths[3] + btnWidths[4] + btnWidths[5] + btnWidths[6] + btnWidths[7] + btnSpacing * 7;

		// Get toolbar client area
		RECT rcToolbar;
		GetClientRect(hToolBar1, &rcToolbar);

		// Calculate starting X and Y to center horizontally and vertically
		int startX = (rcToolbar.right - totalBtnWidth) / 2;
		int startY = (rcToolbar.bottom - btnHeights) / 2;

		// Create buttons
		hBtnUp1 = CreateWindow("BUTTON", "Up", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_FLAT,
		                       startX, startY, btnWidths[0], btnHeights, hToolBar1, (HMENU)1, GetModuleHandle(NULL), NULL);
		hBtnOpen1 = CreateWindow("BUTTON", "Open", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_FLAT,
		                         startX + btnWidths[0] + btnSpacing, startY, btnWidths[1], btnHeights, hToolBar1, (HMENU)2, GetModuleHandle(NULL), NULL);
		hBtnDownload1 = CreateWindow("BUTTON", "Download", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_FLAT,
		                             startX + btnWidths[0] + btnWidths[1] + btnSpacing * 2, startY, btnWidths[2], btnHeights, hToolBar1, (HMENU)3, GetModuleHandle(NULL), NULL);
		hBtnUploadFile1 = CreateWindow("BUTTON", "Upload File", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_FLAT,
		                               startX + btnWidths[0] + btnWidths[1] + btnWidths[2] + btnSpacing * 3, startY, btnWidths[3], btnHeights, hToolBar1, (HMENU)4, GetModuleHandle(NULL), NULL);
		hBtnUploadFolder1 = CreateWindow("BUTTON", "Upload Folder", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_FLAT,
		                                 startX + btnWidths[0] + btnWidths[1] + btnWidths[2] + btnWidths[3] + btnSpacing * 4, startY, btnWidths[4], btnHeights, hToolBar1, (HMENU)5, GetModuleHandle(NULL), NULL);
		hBtnDelete1 = CreateWindow("BUTTON", "Delete", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_FLAT,
		                           startX + btnWidths[0] + btnWidths[1] + btnWidths[2] + btnWidths[3] + btnWidths[4] + btnSpacing * 5, startY, btnWidths[5], btnHeights, hToolBar1, (HMENU)6, GetModuleHandle(NULL), NULL);
		hBtnSettings1 = CreateWindow("BUTTON", "Settings", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_FLAT,
		                             startX + btnWidths[0] + btnWidths[1] + btnWidths[2] + btnWidths[3] + btnWidths[4] + btnWidths[5] + btnSpacing * 6, startY, btnWidths[6], btnHeights, hToolBar1, (HMENU)7, GetModuleHandle(NULL), NULL);
		hBtnLog1 = CreateWindow("BUTTON", "View Log", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_FLAT,
		                        startX + btnWidths[0] + btnWidths[1] + btnWidths[2] + btnWidths[3] + btnWidths[4] + btnWidths[5] + btnWidths[6] + btnSpacing * 7,
		                        startY, btnWidths[7], btnHeights, hToolBar1, (HMENU)8, GetModuleHandle(NULL), NULL);

		// Disable Windows Theme on Buttons

		SetWindowTheme(hBtnUp1, L" ", L" ");
		SetWindowTheme(hBtnOpen1, L" ", L" ");
		SetWindowTheme(hBtnDownload1, L" ", L" ");
		SetWindowTheme(hBtnUploadFile1, L" ", L" ");
		SetWindowTheme(hBtnUploadFolder1, L" ", L" ");
		SetWindowTheme(hBtnDelete1, L" ", L" ");
		SetWindowTheme(hBtnSettings1, L" ", L" ");
		SetWindowTheme(hBtnLog1, L" ", L" ");

		// Use a custom font
		HFONT hFont = CreateFont( 14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Tahoma");

		// Apply font to buttons
		SendMessage(hBtnUp1, WM_SETFONT, (WPARAM)hFont, TRUE);
		SendMessage(hBtnOpen1, WM_SETFONT, (WPARAM)hFont, TRUE);
		SendMessage(hBtnDownload1, WM_SETFONT, (WPARAM)hFont, TRUE);
		SendMessage(hBtnUploadFile1, WM_SETFONT, (WPARAM)hFont, TRUE);
		SendMessage(hBtnUploadFolder1, WM_SETFONT, (WPARAM)hFont, TRUE);
		SendMessage(hBtnDelete1, WM_SETFONT, (WPARAM)hFont, TRUE);
		SendMessage(hBtnSettings1, WM_SETFONT, (WPARAM)hFont, TRUE);
		SendMessage(hBtnLog1, WM_SETFONT, (WPARAM)hFont, TRUE);

		// Load icons
		HICON hIconUp1 = LoadShellIcon("shell32.dll", 146, 16);
		HICON hIconOpen1 = LoadShellIcon("mmcndmgr.dll", 22, 16);
		HICON hIconDownload1 = LoadShellIcon("netshell.dll", 150, 16);
		HICON hIconUploadFile1 = LoadShellIcon("netshell.dll", 149, 16);
		HICON hIconUploadFolder1 = LoadShellIcon("imageres.dll", 176, 16);
		HICON hIconDelete1 = LoadShellIcon("shell32.dll", 31, 16);
		HICON hIconSettings1 = LoadShellIcon("mmcndmgr.dll", 88, 16);
		HICON hIconLog1 = LoadShellIcon("mmcndmgr.dll", 1, 16);

		// Set icons to buttons
		SendMessage(hBtnUp1, BM_SETIMAGE, IMAGE_ICON, (LPARAM)hIconUp1);
		SendMessage(hBtnOpen1, BM_SETIMAGE, IMAGE_ICON, (LPARAM)hIconOpen1);
		SendMessage(hBtnDownload1, BM_SETIMAGE, IMAGE_ICON, (LPARAM)hIconDownload1);
		SendMessage(hBtnUploadFile1, BM_SETIMAGE, IMAGE_ICON, (LPARAM)hIconUploadFile1);
		SendMessage(hBtnUploadFolder1, BM_SETIMAGE, IMAGE_ICON, (LPARAM)hIconUploadFolder1);
		SendMessage(hBtnDelete1, BM_SETIMAGE, IMAGE_ICON, (LPARAM)hIconDelete1);
		SendMessage(hBtnSettings1, BM_SETIMAGE, IMAGE_ICON, (LPARAM)hIconSettings1);
		SendMessage(hBtnLog1, BM_SETIMAGE, IMAGE_ICON, (LPARAM)hIconLog1);

		// Most buttons Disabled initially
		DisableItemButtons1();

		// Update toolbar height if needed
		RECT rc;
		GetClientRect(hToolBar1, &rc);
		int toolbarHeight = rc.bottom;

		// Create status bar
		hStatusBar1 = CreateWindowEx(0, STATUSCLASSNAME, NULL, WS_CHILD | WS_VISIBLE | CCS_BOTTOM | SBARS_SIZEGRIP, 0, 0, 0, 0, hwnd, (HMENU)1, GetModuleHandle(NULL), NULL);

		g_oldStatusBar1Proc = (WNDPROC)SetWindowLongPtr(hStatusBar1, GWLP_WNDPROC, (LONG_PTR)StatusBar1Proc);

		RECT rcClient;
		GetClientRect(hwnd, &rcClient);
		int parts[] = { rcClient.right / 5, rcClient.right * 2 / 4, -1 }; // 20%, 30%, 50%
		SendMessage(hStatusBar1, SB_SETPARTS, 3, (LPARAM)parts);

		// Set the text of the parts
		status_text1 = "ADB Status";
		status_text2 = "Current Path: " + LS_PATH;
		status_text3 = "Items Selected: None.";
		SendMessage(hStatusBar1, SB_SETTEXT, 0 | SBT_OWNERDRAW, (LPARAM)status_text1.c_str());
		SendMessage(hStatusBar1, SB_SETTEXT, 1, (LPARAM)status_text2.c_str());
		SendMessage(hStatusBar1, SB_SETTEXT, 2, (LPARAM)status_text3.c_str());

		int statusbarHeight = rc.bottom - rc.top;

		// Create ListView
		hListView1 = CreateWindowEx(
		                 WS_EX_CLIENTEDGE,
		                 WC_LISTVIEW,
		                 "",
		                 WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
		                 0, toolbarHeight + GetSystemMetrics(SM_CYMENU) - 20,
		                 clientRect.right, 348 - toolbarHeight - statusbarHeight,
		                 hwnd, nullptr, GetModuleHandle(NULL), nullptr
		             );

		g_oldListView1Proc = (WNDPROC)SetWindowLongPtr(hListView1, GWLP_WNDPROC, (LONG_PTR)CustomListView1Proc);

		ListView_SetExtendedListViewStyle(hListView1, LVS_EX_FULLROWSELECT);

		// Add columns...
		LVCOLUMN col = { 0 };
		col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;

		// Column 0: checkbox column — left
		col.fmt = LVCFMT_CENTER;
		col.pszText = (LPSTR)"";
		col.cx = 25;
		ListView_InsertColumn(hListView1, 0, &col);

		// Column 1: row number — right
		col.fmt = LVCFMT_CENTER;
		col.pszText = (LPSTR)"#";
		col.cx = 25;
		ListView_InsertColumn(hListView1, 1, &col);

		// Column 2: Name — left
		col.fmt = LVCFMT_LEFT;
		col.pszText = (LPSTR)"Name";
		col.cx = 200;
		ListView_InsertColumn(hListView1, 2, &col);

		// Column 3: Type — right
		col.fmt = LVCFMT_RIGHT;
		col.pszText = (LPSTR)"Type";
		col.cx = 100;
		ListView_InsertColumn(hListView1, 3, &col);

		// Column 4: Size — right
		col.fmt = LVCFMT_RIGHT;
		col.pszText = (LPSTR)"Size";
		col.cx = 100;
		ListView_InsertColumn(hListView1, 4, &col);

		// Column 5: Modified — right
		col.fmt = LVCFMT_RIGHT;
		col.pszText = (LPSTR)"Modified";
		col.cx = 150;
		ListView_InsertColumn(hListView1, 5, &col);

		// Column 6: filler — left
		col.fmt = LVCFMT_LEFT;
		col.pszText = (LPSTR)"";
		col.cx = 150;
		ListView_InsertColumn(hListView1, 6, &col);

		HIMAGELIST hDummyImageList = ImageList_Create(1, 23, ILC_COLOR32, 1, 1);
		ListView_SetImageList(hListView1, hDummyImageList, LVSIL_SMALL);

		hListViewStatus1 = CreateWindowEx(0, "STATIC", "This Folder seems to be empty!", WS_CHILD /*| SS_CENTER*/ | SS_NOPREFIX, 27, 80, 300, 20, hwnd, NULL, GetModuleHandle(NULL), NULL);
		hFont = CreateFont(18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Tahoma");
		SendMessage(hListViewStatus1, WM_SETFONT, (WPARAM)hFont, TRUE);

		SetTimer(hListViewWindow1, 1, 3000, Timer1Proc);
		SetTimer(hListViewWindow1, 3, 1500, Timer3Proc);

		EnableWindow(hBtnUp1, FALSE);
		EnableWindow(hBtnOpen1, FALSE);
		EnableWindow(hBtnDownload1, FALSE);
		EnableWindow(hBtnUploadFile1, FALSE);
		EnableWindow(hBtnUploadFolder1, FALSE);
		EnableWindow(hBtnDelete1, FALSE);
		
		break;
	}

	case WM_COMMAND:
		switch (LOWORD(wParam)) {
		case 1:
			LOG_THIS("[ LRESULT CALLBACK hListViewWindow1Proc(....) ] PRELOADFL() called from &MENU...\r\n");
			PRELOADFL();
			break;
		case 2:
			LOG_THIS("[ LRESULT CALLBACK hListViewWindow1Proc(....) ] EXITING PROGRAM from &MENU /// " + GetexePath() + " ...\r\n");
			PostQuitMessage(0);
			break;
		case 3:
			MessageBox(NULL, "Program Created by: unfamiliaz@gmail.com [20251216-20260111].\nPhone/WhatsApp: +256755128366.", APP_TITLE2, MB_OK | MB_ICONINFORMATION);
			break;
		}
		break;

	case WM_SETCURSOR:
		if ((HWND)wParam == hBtnUp1 || (HWND)wParam == hBtnOpen1 || (HWND)wParam == hBtnDownload1 ||
		        (HWND)wParam == hBtnUploadFile1 || (HWND)wParam == hBtnUploadFolder1 || (HWND)wParam == hBtnDelete1 ||
		        (HWND)wParam == hBtnSettings1) {
			SetCursor(LoadCursor(NULL, IDC_HAND));
			return TRUE;
		} else if((HWND)wParam == hStatusBar1) {
			int x, y;
			POINT pt;
			GetCursorPos(&pt);
			ScreenToClient(hStatusBar1, &pt);
			RECT rc;
			SendMessage(hStatusBar1, SB_GETRECT, 0, (LPARAM)&rc);
			if (PtInRect(&rc, pt)) {
				SetCursor(LoadCursor(NULL, IDC_HAND));
				return TRUE;
			}
		} else {
			return DefWindowProc(hwnd, msg, wParam, lParam);
		}
		break;

	case WM_CTLCOLORSTATIC:
		if ((HWND)lParam == hListViewStatus1) {
			HDC hdc = (HDC)wParam;
			SetBkColor(hdc, RGB(255, 255, 255)); // white background
			return (LRESULT)GetStockObject(WHITE_BRUSH);
		} else {
			return DefWindowProc(hwnd, msg, wParam, lParam);
		}
		break;

	case WM_SIZE: {
		RECT rcClient;
		GetClientRect(hwnd, &rcClient);

		// Resize toolbar
		MoveWindow(hToolBar1, 0, 0, rcClient.right, 46, TRUE);

		// Recalculate button positions
		RECT rcToolbar;
		GetClientRect(hToolBar1, &rcToolbar);
		int btnSpacing = 6;
		int btnHeights = 28;
		int btnWidths[] = { 45, 60, 80, 90, 100, 65, 75, 80 };
		int totalBtnWidth = btnWidths[0] + btnWidths[1] + btnWidths[2] + btnWidths[3] + btnWidths[4] + btnWidths[5] + btnWidths[6] + btnWidths[7] + btnSpacing * 7;
		int startX = (rcToolbar.right - totalBtnWidth) / 2;
		int startY = (rcToolbar.bottom - btnHeights) / 2;

		ShowWindow(hToolBar1, SW_HIDE);

		// Move buttons to new positions
		MoveWindow(hBtnUp1, startX, startY, btnWidths[0], btnHeights, TRUE);
		MoveWindow(hBtnOpen1, startX + btnWidths[0] + btnSpacing, startY, btnWidths[1], btnHeights, TRUE);
		MoveWindow(hBtnDownload1, startX + btnWidths[0] + btnWidths[1] + btnSpacing * 2, startY, btnWidths[2], btnHeights, TRUE);
		MoveWindow(hBtnUploadFile1, startX + btnWidths[0] + btnWidths[1] + btnWidths[2] + btnSpacing * 3, startY, btnWidths[3], btnHeights, TRUE);
		MoveWindow(hBtnUploadFolder1, startX + btnWidths[0] + btnWidths[1] + btnWidths[2] + btnWidths[3] + btnSpacing * 4, startY, btnWidths[4], btnHeights, TRUE);
		MoveWindow(hBtnDelete1, startX + btnWidths[0] + btnWidths[1] + btnWidths[2] + btnWidths[3] + btnWidths[4] + btnSpacing * 5, startY, btnWidths[5], btnHeights, TRUE);
		MoveWindow(hBtnSettings1, startX + btnWidths[0] + btnWidths[1] + btnWidths[2] + btnWidths[3] + btnWidths[4] + btnWidths[5] + btnSpacing * 6, startY, btnWidths[6], btnHeights, TRUE);
		MoveWindow(hBtnLog1, startX + btnWidths[0] + btnWidths[1] + btnWidths[2] + btnWidths[3] + btnWidths[4] + btnWidths[5] + btnWidths[6] + btnSpacing * 7, startY, btnWidths[7], btnHeights, TRUE);

		ShowWindow(hToolBar1, SW_SHOW);

		InvalidateRect(hToolBar1, NULL, TRUE);

		// Resize status bar
		SendMessage(hStatusBar1, WM_SIZE, 0, 0);

		// Update status bar parts
		RECT rcStatusBar;
		GetClientRect(hwnd, &rcStatusBar);
		int parts[] = { rcStatusBar.right / 5 + 20, rcStatusBar.right * 2 / 4, -1 }; // 20%, 30%, 50%
		SendMessage(hStatusBar1, SB_SETPARTS, 3, (LPARAM)parts);

		// Resize list view
		GetWindowRect(hStatusBar1, &rcStatusBar);
		int statusbarHeight = rcStatusBar.bottom - rcStatusBar.top;
		MoveWindow(hListView1, 0, 46, rcClient.right, rcClient.bottom - 46 - statusbarHeight, TRUE);

		// Get width of columns 0-5
		int totalWidth = 0;
		for (int i = 0; i < 6; i++) {
			totalWidth += ListView_GetColumnWidth(hListView1, i);
		}

		// Resize last column (index 6) to remaining width
		int newWidth = rcClient.right - totalWidth;
		if (newWidth > 0) {
			ListView_SetColumnWidth(hListView1, 6, newWidth - 10);
		}

		// Center hListViewStatus1 on top of hListView1

		/*RECT listViewRect;
		GetClientRect(hListView1, &listViewRect);
		int statusWidth = 300;
		int statusHeight = 20;
		int x = (listViewRect.right - statusWidth) / 2;
		int y = (listViewRect.bottom - statusHeight) / 2 - 20; // adjust y position
		MoveWindow(hListViewStatus1, x, y, statusWidth, statusHeight, TRUE);*/
		InvalidateRect(hListViewStatus1, NULL, TRUE);

		// Update maximum characters display in status text 3

		RECT rc;
		GetClientRect(hStatusBar1, &rc);
		int partWidth = rc.right / 3 - 10;
		HDC hdc = GetDC(hStatusBar1);
		HFONT hFont = (HFONT)SendMessage(hStatusBar1, WM_GETFONT, 0, 0);
		HFONT hOldFont = (HFONT)SelectObject(hdc, hFont);
		SIZE sz;
		GetTextExtentPoint32(hdc, "X", 1, &sz);
		maxDisplayChars = partWidth / sz.cx + 30;
		SelectObject(hdc, hOldFont);
		ReleaseDC(hStatusBar1, hdc);
		UpdateStatusBarSelection();

		SaveMainWindowSettings(true);

	}
	break;

	case WM_MOVE:
		SaveMainWindowSettings(false);
		break;

	case WM_NOTIFY: {
		LPNMHDR nmhdr = (LPNMHDR)lParam;

		if (nmhdr->hwndFrom == hListView1 && nmhdr->code == NM_CUSTOMDRAW) {
			LPNMLVCUSTOMDRAW cd = (LPNMLVCUSTOMDRAW)lParam;

			switch (cd->nmcd.dwDrawStage) {
			case CDDS_PREPAINT:
				return CDRF_NOTIFYITEMDRAW;

			case CDDS_ITEMPREPAINT: {
				int row = (int)cd->nmcd.dwItemSpec;
				RECT rowRect;
				ListView_GetItemRect(hListView1, row, &rowRect, LVIR_BOUNDS);

				bool isSelected = (row == g_selectedRow);
				bool isChecked = g_checked[row];

				if (isSelected || isChecked) {
					HBRUSH bgBrush = CreateSolidBrush(RGB(51, 153, 255)); // blue background
					FillRect(cd->nmcd.hdc, &rowRect, bgBrush);
					DeleteObject(bgBrush);
				} else {
					HBRUSH bgBrush = CreateSolidBrush(row % 2 ? RGB(240, 240, 240) : RGB(255, 255, 255));
					FillRect(cd->nmcd.hdc, &rowRect, bgBrush);
					DeleteObject(bgBrush);
				}

				return CDRF_NOTIFYSUBITEMDRAW;
			}

			case CDDS_SUBITEM | CDDS_ITEMPREPAINT: {
				int row = (int)cd->nmcd.dwItemSpec;
				int col = cd->iSubItem;

				RECT rc;
				ListView_GetSubItemRect(hListView1, row, col, LVIR_BOUNDS, &rc);

				bool isSelected = (row == g_selectedRow);
				bool isChecked = g_checked[row];
				bool highlight = isSelected || isChecked;

				DrawListViewCell(cd->nmcd.hdc, rc, row, col, highlight, reverse_list);

				return CDRF_SKIPDEFAULT;
			}

			}

		}

		if (nmhdr->hwndFrom == hListView1 && nmhdr->code == LVN_COLUMNCLICK) {
			NMLISTVIEW* pnm = (NMLISTVIEW*)lParam;
			LV1_LastSortColumn = pnm->iSubItem;
			SortFileEntries();
		}

		break;
	}

	case WM_KEYDOWN: {
		if (wParam == VK_UP || wParam == VK_DOWN) {
			if (wParam == VK_UP) { // up arrow
				g_listViewIndex--;
				if (g_listViewIndex < 0) {
					g_listViewIndex = ListView_GetItemCount(hListView1) - 1;
				}
			} else if (wParam == VK_DOWN) { // down arrow
				g_listViewIndex++;
				if (g_listViewIndex >= ListView_GetItemCount(hListView1)) {
					g_listViewIndex = 0;
				}
			}
			HandleNormalClickSelection(hListView1, g_listViewIndex);
			ListView_EnsureVisible(hListView1, g_listViewIndex, FALSE);
			SelectedIndex = g_listViewIndex;
			return 0;
		}
		break;
	}

	case WM_DRAWITEM: {
		DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lParam;
		if (dis->CtlID == 1) { // Check if it's our status bar
			if (dis->itemID == 0) { // First part
				HBRUSH hBrush = CreateSolidBrush(RGB(0, 0, 0)); // Black background
				FillRect(dis->hDC, &dis->rcItem, hBrush);
				DeleteObject(hBrush);

				LOGFONT lf;
				lf.lfHeight = -MulDiv(8, GetDeviceCaps(dis->hDC, LOGPIXELSY), 72); // 8pt
				lf.lfWidth = 0;
				lf.lfEscapement = 0;
				lf.lfOrientation = 0;
				lf.lfWeight = FW_BOLD;
				lf.lfItalic = FALSE;
				lf.lfUnderline = FALSE;
				lf.lfStrikeOut = FALSE;
				lf.lfCharSet = DEFAULT_CHARSET;
				lf.lfOutPrecision = OUT_DEFAULT_PRECIS;
				lf.lfClipPrecision = CLIP_DEFAULT_PRECIS;
				lf.lfQuality = DEFAULT_QUALITY;
				lf.lfPitchAndFamily = DEFAULT_PITCH | FF_SWISS;
				strcpy(lf.lfFaceName, "Arial");

				HFONT hFont = CreateFontIndirect(&lf);
				HFONT hOldFont = (HFONT)SelectObject(dis->hDC, hFont);

				if (flashStatus && flashVisible) {
					SetTextColor(dis->hDC, RGB(255, 25, 25)); // Flashing red color
				} else if (flashStatus && !flashVisible) {
					SetTextColor(dis->hDC, RGB(0, 0, 0)); // Black color (same as background)
				} else {
					SetTextColor(dis->hDC, RGB(91, 253, 176)); // Normal color
				}

				SetBkMode(dis->hDC, TRANSPARENT);
				DrawText(dis->hDC, adb_status1.c_str(), -1, &dis->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

				SelectObject(dis->hDC, hOldFont);
				DeleteObject(hFont);
				return TRUE;
			}
		}
	}
	break;

	case WM_DESTROY:
		SaveMainWindowSettings(false);
		cleanupOfflineFLF();
		LOG_THIS("[ LRESULT CALLBACK hListViewWindow1Proc(....) ] EXITING PROGRAM /// " + GetexePath() + " ...\r\n");
		PostQuitMessage(0);

		break;

	default:
		return DefWindowProc(hwnd, msg, wParam, lParam);
	}

	return 0;

}

LRESULT CALLBACK CustomListView1Proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg) {

	case WM_MOUSEMOVE: {
		if (!g_trackingMouse) {
			TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, hwnd, 0 };
			TrackMouseEvent(&tme);
			g_trackingMouse = true;
		}
		POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
		UpdateHoveredRow(hwnd, pt);
		if (g_hoveredRow != -1 && SW1usctoiCB1) {
			SetCursor(LoadCursor(NULL, IDC_HAND)); // Hand cursor
		} else {
			SetCursor(LoadCursor(NULL, IDC_ARROW)); // Pointer cursor
		}
		break;
	}

	case WM_MOUSELEAVE: {
		g_trackingMouse = false;
		if (g_hoveredRow != -1) {
			RECT rc;
			ListView_GetItemRect(hwnd, g_hoveredRow, &rc, LVIR_BOUNDS);
			InvalidateRect(hwnd, &rc, FALSE);
			g_hoveredRow = -1;
		}
		SetCursor(LoadCursor(NULL, IDC_ARROW)); // Pointer cursor
		break;
	}

	case WM_LBUTTONDOWN: {
		SetFocus(hListViewWindow1);
		POINT pt = { LOWORD(lParam), HIWORD(lParam) };
		LVHITTESTINFO hit = { 0 };
		hit.pt = pt;
		int index = ListView_HitTest(hwnd, &hit);
		SelectedIndex = index;
		g_listViewIndex = index;
		if (index >= 0 && (hit.flags & LVHT_ONITEM)) {
			if (IsPointInCheckbox(hwnd, index, pt)) {
				ToggleCheckbox(hwnd, index);
				ClearHoveredRowIfSelectedOrChecked(hwnd);
				return 0;
			}
			if (IsAnyCheckboxChecked()) {
				// Ignore normal selection if checkboxes are active
				return 0;
			}
			if(SW1usctoiCB1)
			{
				OpenItem((LS_PATH + entries[index].Name).c_str(), entries[index].Type, entries[index].Size);
			}
			else
			{
				HandleNormalClickSelection(hwnd, index); 
			}
			ClearHoveredRowIfSelectedOrChecked(hwnd);
			return 0;
		}
		break;
	}

	case WM_LBUTTONDBLCLK: {
		POINT pt = { LOWORD(lParam), HIWORD(lParam) };

		LVHITTESTINFO hit = { 0 };
		hit.pt = pt;
		int index = ListView_HitTest(hwnd, &hit);
		SelectedIndex = index;
		g_listViewIndex = index;
		if (index >= 0 && (hit.flags & LVHT_ONITEM)) {
			// Handle double-click on item here
			// For example:
			ClearHoveredRowIfSelectedOrChecked(hwnd);
			if(!SW1usctoiCB1)
			{
				OpenItem((LS_PATH + entries[index].Name).c_str(), entries[index].Type, entries[index].Size);
			}
			return 0;
		}
		break;
	}

	case WM_KEYDOWN:
		//MBD();
		break;

	}

	return CallWindowProc(g_oldListView1Proc, hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK hToolBar1Proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg) {
	case WM_COMMAND: {
		int controlID = LOWORD(wParam);
		switch (controlID) {
		case 1: {
			if (LS_PATH == GetSDParentDir(LS_PATH)) break;
			LS_PATH = GetSDParentDir(LS_PATH);
			ShowWindow(hListViewStatus1, SW_HIDE);
			std::string currentFL = getADBOutput();
			entries = parseFileList(currentFL);
			PopulateListView();
			if (currentFL.empty()) {
				ShowWindow(hListViewStatus1, SW_SHOW);
				EnableWindow(hBtnOpen1, FALSE);
			} else {
				EnableWindow(hBtnOpen1, TRUE);
			}
			status_text2 = "Current Path: " + LS_PATH;
			SendMessage(hStatusBar1, SB_SETTEXT, 1, (LPARAM)status_text2.c_str());
			std::string wTitle = "ADB File Explorer: " + LS_PATH;
			SetWindowText(hListViewWindow1, wTitle.c_str());
			if (LS_PATH == "/sdcard/") {
				EnableWindow(hBtnUp1, FALSE);
			} else {
				EnableWindow(hBtnUp1, TRUE);
			}
			break;
		}
		case 2: {
			HandleNormalClickSelection(hwnd, SelectedIndex);
			OpenItem((LS_PATH + entries[SelectedIndex].Name).c_str(), entries[SelectedIndex].Type, entries[SelectedIndex].Size);
			ClearHoveredRowIfSelectedOrChecked(hwnd);
			break;
		}
		case 3: {
			TryDownloading();
			break;
		}
		case 4: {
			TryUploading(1);
			break;
		}
		case 5: {
			TryUploading(2);
			break;
		}
		case 6: {
			TryDeleting();
			break;
		}
		case 7: {
			StartSettingsWindow1();
			break;
		}
		case 8: {
			StartLogViewWindow1();
			break;
		}
		}
		SetFocus(hListViewWindow1);
		return 0;
	}
	}

	// Call original proc for default handling
	return CallWindowProc(g_oldToolBar1Proc, hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK StatusBar1Proc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg) {
	}
	return CallWindowProc(g_oldStatusBar1Proc, hWnd, msg, wParam, lParam);
}

LRESULT CALLBACK SettingsWindow1Proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg) {

	case WM_COMMAND: {

		if (HIWORD(wParam) == BN_CLICKED && (LOWORD(wParam) > 3 && LOWORD(wParam) < 10)) {
			SendMessage(GetDlgItem(hwnd, LOWORD(wParam)), BM_SETCHECK, !SendMessage(GetDlgItem(hwnd, LOWORD(wParam)), BM_GETCHECK, 0, 0), 0);
			SW1rmwpCB1 = SendDlgItemMessage(hwnd, 4, BM_GETCHECK, 0, 0) == BST_CHECKED;
			SW1epciscCB1 = SendDlgItemMessage(hwnd, 5, BM_GETCHECK, 0, 0) == BST_CHECKED;
			SW1rwlbCB1 = SendDlgItemMessage(hwnd, 6, BM_GETCHECK, 0, 0) == BST_CHECKED;
			SW1sbofdiCB1 = SendDlgItemMessage(hwnd, 7, BM_GETCHECK, 0, 0) == BST_CHECKED;
			SW1cbpCB1 = SendDlgItemMessage(hwnd, 8, BM_GETCHECK, 0, 0) == BST_CHECKED;
			SW1usctoiCB1 = SendDlgItemMessage(hwnd, 9, BM_GETCHECK, 0, 0) == BST_CHECKED;
			WRSS("RestoreMainWindowPosition", SW1rmwpCB1 ? "Yes" : "No");
			WRSS("EscapeADBShellCommand", SW1epciscCB1 ? "Yes" : "No");
			WRSS("RewriteTEXT2WindowLinesBreaks", SW1rwlbCB1 ? "Yes" : "No");
			WRSS("BackUpDeletedItems", SW1sbofdiCB1 ? "Yes" : "No");
			WRSS("CacheFileLists", SW1cbpCB1 ? "Yes" : "No");
			WRSS("UseSingleClickInFileList", SW1usctoiCB1 ? "Yes" : "No");
			return 0;
		}

		else if (HIWORD(wParam) == BN_CLICKED && LOWORD(wParam) == 2 && !FUNC2Running) {
			if(FUNC2Running) return 0;
			FUNC2Running = true;
			std::string filePath = BrowseForFile();
			if(!filePath.empty() && GetFileExtension(filePath) == "exe") {
				char buffer[1024];
				SendMessage(hSettingsWindow1ADBPath1, WM_GETTEXT, 1024, (LPARAM)buffer);
				std::string p_adbPath(buffer);
				adbPath = filePath;
				if(!isADBconnected()) {
					adbPath = p_adbPath;
				}
				SendMessage(hSettingsWindow1ADBPath1, WM_SETTEXT, 0, (LPARAM)adbPath.c_str());
				WRSS("adbPath", adbPath);
			}
			FUNC2Running = false;
			return 0;
		}

		else if (HIWORD(wParam) == BN_CLICKED && LOWORD(wParam) == 3) {
			if (file_exists("G:\\scrcpy\\adb.exe")) {
				adbPath = "G:\\scrcpy\\adb.exe";
			} else {
				adbPath = GetExeFolder() + "adb.exe";
			}
			SendMessage(hSettingsWindow1ADBPath1, WM_SETTEXT, 0, (LPARAM)adbPath.c_str());
			if (MessageBox(NULL,"This will also DELETE all registered settings...?",APP_TITLE2,MB_OKCANCEL|MB_ICONWARNING)==IDOK)
			{
				RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\ADBFE\\v1.0.0.0");
				SW1rmwpCB1 = true;
				SW1epciscCB1 = true;
				SW1rwlbCB1 = true;
				SW1sbofdiCB1 = false;
				SW1cbpCB1 = true;
				SW1usctoiCB1 = false;
				DestroyWindow(hSettingsWindow1);
				StartSettingsWindow1();
			}
			return 0;
		}

		break;
	}

	case WM_CLOSE:
		DestroyWindow(hwnd);
		if (IsWindow(hListViewWindow1)) {
			SetForegroundWindow(hListViewWindow1);
		}
		break;
	default:
		return DefWindowProc(hwnd, msg, wParam, lParam);
	}
	return 0;
}

LRESULT CALLBACK SW1rmwpCB1Proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg) {
	case WM_SETFOCUS:
		return 0;
	default:
		return CallWindowProc(g_oldSW1rmwpCB1Proc, hwnd, msg, wParam, lParam);
	}
}

LRESULT CALLBACK SW1epciscCB1Proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg) {
	case WM_SETFOCUS:
		return 0;
	default:
		return CallWindowProc(g_oldSW1epciscCB1Proc, hwnd, msg, wParam, lParam);
	}
}

LRESULT CALLBACK SW1rwlbCB1Proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg) {
	case WM_SETFOCUS:
		return 0;
	default:
		return CallWindowProc(g_oldSW1rwlbCB1Proc, hwnd, msg, wParam, lParam);
	}
}

LRESULT CALLBACK SW1sbofdiCB1Proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg) {
	case WM_SETFOCUS:
		return 0;
	default:
		return CallWindowProc(g_oldSW1sbofdiCB1Proc, hwnd, msg, wParam, lParam);
	}
}

LRESULT CALLBACK hSW1cbpCB1Proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg) {
	case WM_SETFOCUS:
		return 0;
	default:
		return CallWindowProc(g_oldSW1cbpCB1Proc, hwnd, msg, wParam, lParam);
	}
}

LRESULT CALLBACK SW1usctoiCB1Proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg) {
	case WM_SETFOCUS:
		return 0;
	default:
		return CallWindowProc(g_oldSW1usctoiCB1Proc, hwnd, msg, wParam, lParam);
	}
}

LRESULT CALLBACK LogViewWindow1Proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg) {
	case WM_COMMAND:
		if (HIWORD(wParam) == BN_CLICKED && LOWORD(wParam) == 2) {
			RefreshTheLogView1();
			return 0;
		} else if (HIWORD(wParam) == BN_CLICKED && LOWORD(wParam) == 4) {
			bool ELTemp1 = EnableLoggingCB1;
			bool ELTemp2 = !ELTemp1;
			EnableLoggingCB1 = true;
			LOG_THIS("[ LRESULT CALLBACK LogViewWindow1Proc(....) ] LOGGING "+std::string(ELTemp2 ? "ENABLED" : "DISABLED")+"...\r\n");
			EnableLoggingCB1 = ELTemp2;
			SendMessage(GetDlgItem(hwnd, 4), BM_SETCHECK, !SendMessage(GetDlgItem(hwnd, 4), BM_GETCHECK, 0, 0), 0);
			WRSS("EnableLogging", EnableLoggingCB1 ? "Yes" : "No");
			RefreshTheLogView1();
			return 0;
		} else if (HIWORD(wParam) == BN_CLICKED && LOWORD(wParam) == 3) {
			DeleteAllLogs1();
			RefreshTheLogView1();
			return 0;
		}
		break;
	case WM_CTLCOLORSTATIC:
		if ((HWND)lParam == hEnableLoggingLabel1 || (HWND)lParam == hEnableLoggingCheckbox1) {
			HDC hdc = (HDC)wParam;
			SetBkColor(hdc, RGB(197, 197, 226));
			return (LRESULT)CreateSolidBrush(RGB(197, 197, 226));
		} else {
			return DefWindowProc(hwnd, msg, wParam, lParam);
		}
		break;
	case WM_CLOSE:
		DestroyWindow(hwnd);
		if (IsWindow(hListViewWindow1)) {
			SetForegroundWindow(hListViewWindow1);
		}
		break;
	default:
		return DefWindowProc(hwnd, msg, wParam, lParam);
	}
	return 0;
}

LRESULT CALLBACK Checkbox1Proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg) {
	case WM_SETFOCUS:
		return 0;
	default:
		return CallWindowProc(g_oldCheckbox1Proc, hwnd, msg, wParam, lParam);
	}
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{

	LOG_THIS("[ int WINAPI WinMain(....) ] PROGRAM STARTED as /// " + GetexePath() + " ...\r\n");

	// Check if another instance is already running
	HWND hwndExisting = FindWindow("ADBFE_CPP_ListViewWindow1", NULL);
	if (hwndExisting != NULL) {
		LOG_THIS("[ int WINAPI WinMain(....) ] Found Another Instance of Program Running, Now Restoring It...\r\n");
		ShowWindow(hwndExisting, SW_MAXIMIZE); // Restore if minimized
		SetForegroundWindow(hwndExisting);
		return 0;
	}

	if(GRSS("RestoreMainWindowPosition", "Yes") == "No") {
		SW1rmwpCB1 = false;
	}
	if(GRSS("EscapeADBShellCommand", "Yes") == "No") {
		SW1epciscCB1 = false;
	}
	if(GRSS("RewriteTEXT2WindowLinesBreaks", "Yes") == "No") {
		SW1rwlbCB1 = false;
	}
	if(GRSS("BackUpDeletedItems", "No") == "Yes") {
		SW1sbofdiCB1 = true;
	}
	if(GRSS("CacheFileLists", "Yes") == "No") {
		SW1cbpCB1 = false;
	}
	if(GRSS("UseSingleClickInFileList", "No") == "Yes") {
		SW1usctoiCB1 = true;
	}
	if(GRSS("EnableLogging", "Yes") == "No") {
		EnableLoggingCB1 = false;
	}
	
	StartFEWindow(hInstance, nCmdShow);

	std::thread([&]() {
		PRELOADFL();
	}).detach();

	MSG msg;
	while (GetMessage(&msg, nullptr, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return (int)msg.wParam;

}

// D:\20251216\mingw32\bin\g++.exe D:\20251216\cpp_listview_test02.cpp -mwindows -static -lcomctl32 -lshell32 -ladvapi32 -Os -s -o D:\20251216\cpp_listview_test02.exe
