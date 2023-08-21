#include <Windows.h>
#include <iostream>
#include <sstream>
#include <TlHelp32.h>
#include <stdlib.h>

using namespace std;

//Become SYSTEM user
//https://www.unknowncheats.me/forum/anti-cheat-bypass/249447-nobastian-universal-ipc-rpc-based-battleye-eac-faceit-esea-mrac-bypass-7.html
bool SetPrivilege(const char * non_rPrivilegeLevel, bool bState = true)
{
	DWORD dwError;
	HANDLE hToken = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		dwError = GetLastError();
		return false;
	}

	TOKEN_PRIVILEGES TokenPrivileges = { 0 };
	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = bState ? SE_PRIVILEGE_ENABLED : 0;

	if (!LookupPrivilegeValue(nullptr, non_rPrivilegeLevel, &TokenPrivileges.Privileges[0].Luid))
	{
		dwError = GetLastError();
		CloseHandle(hToken);
		return false;
	}

	if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
	{
		dwError = GetLastError();
		CloseHandle(hToken);
		return false;
	}

	CloseHandle(hToken);
	return true;
}

//Different values based on task for reference
//https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_privilege_escalation.html
/*
"privileges": {
		"SeBackupPrivilege": "disabled",
		"SeChangeNotifyPrivilege": "enabled-by-default",
		"SeCreateGlobalPrivilege": "enabled-by-default",
		"SeCreatePagefilePrivilege": "disabled",
		"SeCreateSymbolicLinkPrivilege": "disabled",
		"SeDebugPrivilege": "enabled",
		"SeDelegateSessionUserImpersonatePrivilege": "disabled",
		"SeImpersonatePrivilege": "enabled-by-default",
		"SeIncreaseBasePriorityPrivilege": "disabled",
		"SeIncreaseQuotaPrivilege": "disabled",
		"SeIncreaseWorkingSetPrivilege": "disabled",
		"SeLoadDriverPrivilege": "disabled",
		"SeManageVolumePrivilege": "disabled",
		"SeProfileSingleProcessPrivilege": "disabled",
		"SeRemoteShutdownPrivilege": "disabled",
		"SeRestorePrivilege": "disabled",
		"SeSecurityPrivilege": "disabled",
		"SeShutdownPrivilege": "disabled",
		"SeSystemEnvironmentPrivilege": "disabled",
		"SeSystemProfilePrivilege": "disabled",
		"SeSystemtimePrivilege": "disabled",
		"SeTakeOwnershipPrivilege": "disabled",
		"SeTimeZonePrivilege": "disabled",
		"SeUndockPrivilege": "disabled"
	},
*/

//Convert process name to process ID
DWORD FindProcessId(string processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processSnapshot);
	return 0;
}

//Use the standard library to convert a number to a string (char array)
string converter(DWORD hHandleNumber)
{
	ostringstream stream;
	stream << hHandleNumber;
	string str = stream.str();
	return str;
}

//Yo why it break?
void WhyItBraike()
{
	cout << "https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes";
	DWORD error = GetLastError();
	cout << "Error detected, " + converter(error) + " is the value";
}

int main(int argc, char* argv[])
{
	if (argc == 2)
	{
		string processName = argv[0];
		string dllPath = argv[1];

		//Using system(), we can execute any command that can run on terminal if operating system allows.
		//For example, we can call system(“dir”) on Windows and system(“ls”) to list contents of a directory.

		//Windows commands
		string str1 = "chdir";
		string str2 = "dir";
		string str3 = "date";
		string str4 = "whoami";

		// Convert string to const char * as system requires
		// parameter of type const char *
		const char *command1 = str1.c_str();
		const char *command2 = str2.c_str();
		const char *command3 = str3.c_str();
		const char *command4 = str4.c_str();

		//Explain the situation
		cout << "Explaining the situation\n";
		system(command1);
		cout << "\n";
		system(command2);
		cout << "\n";
		system(command3);
		cout << "\n";
		system(command4);
		cout << "\n";

		//I am SYSTEM user
		SetPrivilege("SeDebugPrivilege", true);																															//Function 1
		cout << "I am now SYSTEM\n\n";
		system(command4);
		cout << "I now need to inform you that rats are always at Rabba\n\n";

		//Convert process name to PID
		DWORD pid;
		//pid = FindProcessId("ArmA2OA.exe");												//Function 2
		pid = FindProcessId(processName);																																//Function 2

		/**********************************/
		//Standard DLL injection begins now.
		/**********************************/

		//We we are now SYSTEM, hence our process can always request ALL_ACCESS without worrying about security descriptors.
		//We also choose to inherit SYSTEM level access to all process we launch
		HANDLE hTarget;
		//Opening a new handle
		if (hTarget = OpenProcess(PROCESS_ALL_ACCESS, true, pid))																										//Function 3
		{
			DWORD hNumber = (DWORD)hTarget;
			string handle_number = converter(hNumber);																	//Convert DWORD to string for concatenation
			cout << "Handle Acquired, " + handle_number + " is the value\n";
		}
		else
		{
			WhyItBraike();
		}

		LPSTR pathBuffer = NULL;
		DWORD retStatus;
		//Basically runs DIR and adds the DLL filename to the path to pass to VirtualAllocEx
		retStatus = GetFullPathName(dllPath.c_str(), 4096, pathBuffer, NULL);																							//Function 4
		if (retStatus != 0)
		{
			LPVOID allocatedMemAddr;
			//We now need to allocate memory within the target process using our handle on the process
			allocatedMemAddr = VirtualAllocEx(hTarget, 0, strlen(pathBuffer), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);										//Function 5
			if (allocatedMemAddr != NULL)
			{
				BOOL writeStatus;
				//We now write the path of the DLL to the target process, as this is a standard DLL inection
				//If we wanted to, we could write the full DLL to the target process, which would require our DLL to have a loader
				//If that was the case, we would be doing Reflective DLL injection, which would be an easier, more reliable
				//manual mapping; http://blog.opensecurityresearch.com/2013/01/windows-dll-injection-basics.html
				writeStatus = WriteProcessMemory(hTarget, allocatedMemAddr, pathBuffer, strlen(pathBuffer), NULL);														//Function 6
				if (writeStatus != 0)
				{
					FARPROC loadLibAddr;
					//Find where in the Kernel module's user mode space LoadLibrary() is
					loadLibAddr = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");																//Function 7
					HANDLE hInjDll;
					//Spawn a thread for the module within the target process so it can have CPU time allocated
					hInjDll = CreateRemoteThread(hTarget, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibAddr, NULL, 0, NULL);													//Function 8
					if (hInjDll != NULL)
					{
						string filePath = pathBuffer;
						cout << "Congratulations, your dynamic link library " + filePath + " injected successfully";
					}
					else
					{
						WhyItBraike();
					}
				}
				else
				{
					WhyItBraike();
				}
			}
			else
			{
				WhyItBraike();
			}
		}
		else
		{
			WhyItBraike();
		}
	}
	else
	{
		//Using system(), we can execute any command that can run on terminal if operating system allows.
		//For example, we can call system(“dir”) on Windows and system(“ls”) to list contents of a directory.

		//Windows commands
		string str1 = "chdir";
		string str2 = "dir";
		string str3 = "date";
		string str4 = "whoami";

		// Convert string to const char * as system requires
		// parameter of type const char *
		const char *command1 = str1.c_str();
		const char *command2 = str2.c_str();
		const char *command3 = str3.c_str();
		const char *command4 = str4.c_str();

		//Explain the situation
		cout << "Explaining the situation\n";
		system(command1);
		cout << "\n";
		system(command2);
		cout << "\n";
		system(command3);
		cout << "\n";
		system(command4);
		cout << "\n";

		//I am SYSTEM user
		SetPrivilege("SeDebugPrivilege", true);																															//Function 1
		cout << "I am now SYSTEM\n\n";
		system(command4);
		cout << "I now need to inform you that 99% of Etobicoke is... creatures\n\n"
	}
	
	return 0;
};
