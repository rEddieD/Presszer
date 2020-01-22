#include <Windows.h>
#include <iostream>
#include <io.h>
#include <fcntl.h>
#include <random>
#include <chrono>

bool state = false;
DWORD ThreadID;
HANDLE spamThread;
static HHOOK hhookSysMsg;
std::mt19937* generator;
std::normal_distribution<double> distribution(170.0, 25.0);

DWORD WINAPI SpamKey(LPVOID lpParam)
{
	INPUT input;

	input.type = INPUT_KEYBOARD;
	input.ki.wScan = 0;
	input.ki.time = 0;
	input.ki.dwExtraInfo = 0;

	int keyCode = *(int*)lpParam;

	input.ki.wVk = keyCode;
	input.ki.dwFlags = 0;

	//int min = 100;
	//int max = 260;

	while (state)
	{
		input.ki.dwFlags = 0;
		SendInput(1, &input, sizeof(INPUT));
		/*
		int randNum = rand() % (max - min + 1) + min;
		*/
		double number = distribution(*generator);
		int randNum = number;
		std::cout << "DOWN: " << randNum << std::endl;
		Sleep(randNum);
		input.ki.dwFlags = KEYEVENTF_KEYUP;
		SendInput(1, &input, sizeof(INPUT));
		/*
		randNum = rand() % (max - min + 1) + min;
		*/
		number = distribution(*generator);
		randNum = number;
		std::cout << "UP: " << randNum << std::endl;
		Sleep(randNum);
	}
	return 0;
}

LRESULT CALLBACK CatchKey(int nCode, WPARAM wParam, LPARAM lParam)
{
	if (nCode == HC_ACTION)
	{
		KBDLLHOOKSTRUCT* kbd = (KBDLLHOOKSTRUCT*)lParam;
		if (wParam == WM_KEYDOWN)
		{
			
			DWORD vkCode = kbd->vkCode;
			if (vkCode == 0x30)
			{
				//Change of the state
				state = !state;
				if (state)
				{
					std::cout << "On State" << std::endl;
					ResumeThread(spamThread);
				}
				if (!state)
				{
					std::cout << "Off State" << std::endl;
					SuspendThread(spamThread);
					//thread end the function
				}
			}

		}
	}
	return CallNextHookEx(0, nCode, wParam, lParam);
}

//LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
//{
//	switch (msg)
//	{
//	case WM_CREATE:
//	{
//		HFONT hfDefault;
//		HWND hEdit;
//		HDC dc;
//
//		hEdit = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
//			WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
//			0, 0, 100, 100, hWnd, (HMENU)IDC_MAIN_EDIT, GetModuleHandle(NULL), NULL);
//		if (hEdit == NULL)
//			MessageBox(hWnd, "Could not create edit box.", "Error", MB_OK | MB_ICONERROR);
//
//		dc = GetDC(hWnd);
//
//		hfDefault = (HFONT)SelectObject(dc, GetStockObject(DEFAULT_GUI_FONT));
//		SendMessage(0, WM_SETFONT, (WPARAM)hfDefault, MAKELPARAM(FALSE, 0));
//		ReleaseDC(hWnd, dc);
//	}
//	break;
//	case WM_SIZE:
//	{
//		HWND hEdit;
//		RECT rcClient;
//
//		GetClientRect(hWnd, &rcClient);
//
//		hEdit = GetDlgItem(hWnd, IDC_MAIN_EDIT);
//		SetWindowPos(hEdit, NULL, 0, 0, rcClient.right, rcClient.bottom, SWP_NOZORDER);
//	}
//	break;
//	case WM_LBUTTONDOWN:
//	{
//		char szFileName[MAX_PATH];
//		HINSTANCE hInstance = GetModuleHandle(NULL);
//
//		GetModuleFileName(hInstance, szFileName, MAX_PATH);
//		MessageBox(hWnd, szFileName, "This program is:", MB_OK | MB_ICONINFORMATION);
//	}
//	break;
//	case WM_CLOSE:
//		DestroyWindow(hWnd);
//		break;
//	case WM_DESTROY:
//		PostQuitMessage(0);
//		break;
//	default:
//		return DefWindowProc(hWnd, msg, wParam, lParam);
//	}
//	return 0;
//}

unsigned int long baseAddress = 0x00B41414;
DWORD firstObject = 0xAC;
DWORD nextObject = 0x3C;

//BOOL AdjustPriviledges()
//{
//	HANDLE hToken;
//	TOKEN_PRIVILEGES tokenPriv;
//	LUID luidDebug;
//	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken) != FALSE) {
//		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidDebug) != FALSE)
//		{
//			tokenPriv.PrivilegeCount = 1;
//			tokenPriv.Privileges[0].Luid = luidDebug;
//			tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
//			AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(tokenPriv), NULL, NULL);
//			return true;
//		}
//	}
//	return false;
//}

HANDLE FindProcessID(LPCSTR nameOfProcess)
{
	DWORD PID;
	HWND windowHandle = FindWindow(0, nameOfProcess);
	GetWindowThreadProcessId(windowHandle, &PID);
	if (PID == 0)
	{
		std::cout << "No matching process running" << std::endl;
	}
	else
	{
		std::cout << "Process ID of " << nameOfProcess << " is: " << PID << std::endl;
		HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, PID);
		return processHandle;
	}
	return NULL;
}

void GetAllObjects(HANDLE& pHandle)
{
	DWORD addressContent;
	ReadProcessMemory(pHandle, (void*)(baseAddress), &addressContent, sizeof(addressContent), 0);
	std::cout << "Address of first object: " << std::hex << addressContent << std::endl;
	DWORD addressOfFirstObject;
	ReadProcessMemory(pHandle, (void*)(addressContent + firstObject), &addressOfFirstObject, sizeof(addressOfFirstObject), 0);
	std::cout << "The first object: " << std::hex << addressOfFirstObject << std::endl;
	//Traverse all object
	//Get next object address
	unsigned int counter = 0;
	DWORD nextObjectAddress = addressOfFirstObject;
	while ((nextObjectAddress != NULL) && (counter < 400))
	{
		DWORD lastAddress = nextObjectAddress;
		ReadProcessMemory(pHandle, (void*)(nextObjectAddress + nextObject), &nextObjectAddress, sizeof(nextObjectAddress), 0);
		DWORD currectAddress = nextObjectAddress;
		DWORD difference = currectAddress - lastAddress;
		int type = 0;
		ReadProcessMemory(pHandle, (void*)(currectAddress + 0x14), &type, sizeof(type), 0);
		//Types:
		//1 - item
		//2 - container
		//3 - unit
		//4 - player
		//5 - gameobj
		//6 - dynobj
		//7 - corpse
		if (/*type == 3 ||*/ type == 4)
		{
			float positions[3];
			ReadProcessMemory(pHandle, (void*)(currectAddress + 0x9B8), &positions, sizeof(positions), 0);

			//Get descriptor by 0x8 offset
			DWORD addressOfMobDescriptor;
			ReadProcessMemory(pHandle, (void*)(currectAddress + 0x8), &addressOfMobDescriptor, sizeof(addressOfMobDescriptor), 0);
			int health = 0;
			int maxHealth = 0;
			ReadProcessMemory(pHandle, (void*)(addressOfMobDescriptor + 0x58), &health, sizeof(health), 0);
			ReadProcessMemory(pHandle, (void*)(addressOfMobDescriptor + 0x70), &maxHealth, sizeof(maxHealth), 0);
			std::cout << std::dec << "Health: " << health << "\n";
			std::cout << "Max health: " << maxHealth << "\n";
			int level = 0;
			ReadProcessMemory(pHandle, (void*)(addressOfMobDescriptor + 0x88), &level, sizeof(level), 0);

			std::cout << std::dec << "Level: " << level << " Postition  X: " << positions[0] << " Y: " << positions[1] << " Z: " << positions[2] << std::endl;
		}
		//std::cout << std::hex << nextObjectAddress << std::dec << " Counter: " << ++counter << " " << type << std::hex << " Difference: " << difference << std::endl;
		++counter;
	}
}


int WINAPI WinMain(HINSTANCE hThisInstance, HINSTANCE hPrevInstance, LPSTR lpszArgument, int iCmdShow)
{
	/*WNDCLASSEX wc;
	HWND hWnd;
	wc.cbSize = sizeof(WNDCLASSEX);
	wc.style = 0;
	wc.lpfnWndProc = WndProc;
	wc.cbClsExtra = 0;
	wc.cbWndExtra = 0;
	wc.hInstance = hThisInstance;
	wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
	wc.hCursor = LoadCursor(NULL, IDC_ARROW);
	wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wc.lpszMenuName = NULL;
	wc.lpszClassName = "WindowClassName";
	wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);

	if (!RegisterClassEx(&wc))
	{
		MessageBox(NULL, "Window Registration Failed!", "Error!", MB_ICONEXCLAMATION | MB_OK);
		return 0;
	}

	hWnd = CreateWindowEx(WS_EX_CLIENTEDGE, "WindowClassName", "Presszer", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 240, 120, NULL, NULL,
		hThisInstance, NULL);

	if (hWnd == NULL)
	{
		MessageBox(NULL, "Window Creation Failed!", "Error!", MB_ICONEXCLAMATION | MB_OK);
		return 0;
	}

	ShowWindow(hWnd, iCmdShow);
	UpdateWindow(hWnd);

	*/



	//Allocating console window and connecting the appropiate IO channels with it
	//---------------------------------------------------------------------------
	AllocConsole();

	HANDLE handle_out = GetStdHandle(STD_OUTPUT_HANDLE);
	int hCrt = _open_osfhandle((long)handle_out, _O_TEXT);
	FILE* hf_out = _fdopen(hCrt, "w");
	setvbuf(hf_out, NULL, _IONBF, 1);
	*stdout = *hf_out;
	freopen_s(&hf_out,"CONOUT$", "w", stdout);

	HANDLE handle_in = GetStdHandle(STD_INPUT_HANDLE);
	hCrt = _open_osfhandle((long)handle_in, _O_TEXT);
	FILE* hf_in = _fdopen(hCrt, "r");
	setvbuf(hf_in, NULL, _IONBF, 128);
	*stdin = *hf_in;
	freopen_s(&hf_in, "CONIN$", "r", stdin);
	//---------------------------------------------------------------------------

	//AdjustPriviledges();
	HANDLE processHandle = FindProcessID("GAME_PROCESS_NAME");
	if (processHandle)
	{
		while (true)
		{
			system("cls");
			GetAllObjects(processHandle);
			Sleep(1000);
		}
	}
	else
	{
		std::cout << "No process has been found. (Try to run in administrator mode)\n";
	}
	std::cin.get();


	//Set global hook function
	hhookSysMsg = SetWindowsHookEx(WH_KEYBOARD_LL, (HOOKPROC)CatchKey, 0, 0);

	//Initialize random generator
	unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
	generator = &(std::mt19937(seed));
	
	//Set key to press
	int keyCode = 0x31;

	//Create thread with spamkey function
	spamThread = CreateThread(NULL, 0, SpamKey, &keyCode, CREATE_SUSPENDED, &ThreadID);
	if (spamThread == NULL)
	{
		std::cout << "Thread creation failed: " << GetLastError() << std::endl;
	}
	std::cout << "Thread creation successful " << std::endl;

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 804);

	//Message loop of the function
	MSG Msg;
	while (GetMessage(&Msg, NULL, 0, 0) > 0)
	{
		TranslateMessage(&Msg);
		DispatchMessage(&Msg);
	}

	UnhookWindowsHookEx(hhookSysMsg);

	return 0;
}