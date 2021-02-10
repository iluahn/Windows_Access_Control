#define _CRT_SECURE_NO_WARNINGS
#define _WIN32_WINNT 0x0500

#ifndef UNICODE
#define UNICODE
#endif

//#include <wntdll.h>
#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <aclapi.h>
#include <sddl.h>
#include <iostream>
using namespace std;


//Вывод масок для Show_ACL
HRESULT DisplayPermissions(ACCESS_MASK amMask)
{
	printf("RIGHTS\n");
	//SPECIFIC
	printf("Specific:\n");
	if ((amMask & 0x01) == 0x01)
	{
		//wprintf(L"\tСодержание папки/Чтение данных\n");
		wprintf(L"\tFolder contents/Read data\n");
	}
	if ((amMask & 0x02) == 0x02)
	{
		//wprintf(L"\tСоздание файлов/Запись данных\n");
		wprintf(L"\tCreate file/Write data\n");
	}
	if ((amMask & 0x04) == 0x04)
	{
		//wprintf(L"\tСоздание папок/Дозапись данных\n");
		wprintf(L"\tCreate folder/Append data\n");
	}
	if ((amMask & 0x20) == 0x20)
	{
		//wprintf(L"\tТраверс папок/Выполнение файлов\n");
		wprintf(L"\tFolder travers/File execute\n");
	}
	if ((amMask & FILE_READ_EA) == FILE_READ_EA)
	{
		//wprintf(L"\tЧтение дополнительных атрибутов\n");
		wprintf(L"\tRead extended attributes\n");
	}
	if ((amMask & FILE_WRITE_EA) == FILE_WRITE_EA)
	{
		//wprintf(L"\tЗапись дополнительных атрибутов\n");
		wprintf(L"\tWrite extended attributes\n");
	}
	if ((amMask & FILE_DELETE_CHILD) == FILE_DELETE_CHILD)
	{
		//wprintf(L"\tУдаление директории\n");
		wprintf(L"\tDelete child (directory)\n");
	}
	if ((amMask & FILE_READ_ATTRIBUTES) == FILE_READ_ATTRIBUTES)
	{
		//wprintf(L"\tЧтение атрибутов\n");
		wprintf(L"\tRead attributes\n");
	}
	if ((amMask & FILE_WRITE_ATTRIBUTES) == FILE_WRITE_ATTRIBUTES)
	{
		//wprintf(L"\tЗапись атрибутов\n");
		wprintf(L"\tWrite attributes\n");
	}

	//STANDARD
	printf("Standard:\n");
	if ((amMask & READ_CONTROL) == READ_CONTROL)
	{
		wprintf(L"\tRead control\n");
	}
	if ((amMask & DELETE) == DELETE)
	{
		wprintf(L"\tRight to delete object\n");
	}
	if ((amMask & WRITE_DAC) == WRITE_DAC)
	{
		wprintf(L"\tRight to modify DACL\n");
	}
	if ((amMask & WRITE_OWNER) == WRITE_OWNER)
	{
		wprintf(L"\tRight to change owner\n");
	}
	if ((amMask & SYNCHRONIZE) == SYNCHRONIZE)
	{
		wprintf(L"\tRight to use object for synchronization\n");
	}

	//GENERIC
	printf("Generic:\n");
	if ((amMask & FILE_READ_ATTRIBUTES) == FILE_READ_ATTRIBUTES
		&&
		(amMask & FILE_EXECUTE) == FILE_EXECUTE
		&&
		(amMask & READ_CONTROL) == READ_CONTROL
		&&
		(amMask & SYNCHRONIZE) == SYNCHRONIZE
		) 
	{
		wprintf(L"\tGeneric execute\n");
	}
	if ((amMask & FILE_READ_ATTRIBUTES) == FILE_READ_ATTRIBUTES
		&&
		(amMask & FILE_READ_DATA) == FILE_READ_DATA
		&&
		(amMask & FILE_READ_EA) == FILE_READ_EA
		&&
		(amMask & READ_CONTROL) == READ_CONTROL
		&&
		(amMask & SYNCHRONIZE) == SYNCHRONIZE
		)
	{
		wprintf(L"\tGeneric read\n");
	}
	if ((amMask & FILE_WRITE_ATTRIBUTES) == FILE_WRITE_ATTRIBUTES
		&&
		(amMask & FILE_WRITE_DATA) == FILE_WRITE_DATA
		&&
		(amMask & FILE_WRITE_EA) == FILE_WRITE_EA
		&&
		(amMask & FILE_APPEND_DATA) == FILE_APPEND_DATA
		&&
		(amMask & READ_CONTROL) == READ_CONTROL
		&&
		(amMask & SYNCHRONIZE) == SYNCHRONIZE
		)
	{
		wprintf(L"\tGeneric write\n");
	}
	if ((amMask & FILE_READ_DATA) == FILE_READ_DATA
		&&
		(amMask & FILE_WRITE_DATA) == FILE_WRITE_DATA
		&&
		(amMask & FILE_APPEND_DATA) == FILE_APPEND_DATA
		&&
		(amMask & FILE_READ_EA) == FILE_READ_EA
		&&
		(amMask & FILE_WRITE_EA) == FILE_WRITE_EA
		&&
		(amMask & FILE_EXECUTE) == FILE_EXECUTE
		&&
		(amMask & FILE_DELETE_CHILD) == FILE_DELETE_CHILD
		&&
		(amMask & FILE_READ_ATTRIBUTES) == FILE_READ_ATTRIBUTES
		&&
		(amMask & FILE_WRITE_ATTRIBUTES) == FILE_WRITE_ATTRIBUTES
		&&
		(amMask & DELETE) == DELETE
		&&
		(amMask & READ_CONTROL) == READ_CONTROL
		&&
		(amMask & WRITE_DAC) == WRITE_DAC
		&&
		(amMask & WRITE_OWNER) == WRITE_OWNER
		&&
		(amMask & SYNCHRONIZE) == SYNCHRONIZE
		
		)
	{
		wprintf(L"\tGeneric all\n");
	}

	
	return S_OK;
}

//Вывод ACL
void Show_ACL(wchar_t * wchDirName)
{
	PSECURITY_DESCRIPTOR lpSd = NULL; // указатель на дескриптор безопасности
	PACL lpDacl;               // указатель на список DACL
	PEXPLICIT_ACCESS lpEa;     // указатель на массив элементов типа 
							   // EXPLICIT_ACCESS
	ULONG ulCount;     // количество элементов в массиве

	LPTSTR  lpStringSid = NULL;    // указатель на строку с SID

	DWORD dwErrCode;   // код возврата

	DWORD dwLength;
	//Получаем длину дескриптора безопасности
	if (!GetFileSecurityW(
		wchDirName, //имя файла
		DACL_SECURITY_INFORMATION, //получаем DACL
		lpSd, //адрес дескриптора безопасности
		0, //определяем длину буфера
		&dwLength)) //адрес для требуемой длины
	{
		dwErrCode = GetLastError();
		if (dwErrCode != ERROR_INSUFFICIENT_BUFFER)
		{
			printf("Error file security 1: %u\n", dwErrCode);
		}
	}
	//распределяем память для дескриптора безопасности
	lpSd = (PSECURITY_DESCRIPTOR)malloc((size_t)dwLength);
	//читаем дескриптор безопасности 
	if (!GetFileSecurityW(
		wchDirName,
		DACL_SECURITY_INFORMATION,
		lpSd,
		dwLength,
		&dwLength))
	{
		dwErrCode = GetLastError();
		if (dwErrCode != ERROR_INSUFFICIENT_BUFFER)
		{
			printf("Error file security 2: %u\n", dwErrCode);
		}
	}

	BOOL bDaclPresent;
	BOOL bDaclDefaulted;
	//получаем список DACL из дескриптора безопасности 
	if (!GetSecurityDescriptorDacl(
		lpSd,              //адрес дескриптора безопасности 
		&bDaclPresent,     //признак присутствия DACL
		&lpDacl,           //адрес указателя на DACL
		&bDaclDefaulted))  //признак списка DACL по умолчанию
	{
		dwErrCode = GetLastError();
	}

	ACCESS_ALLOWED_ACE * pAce = NULL;

	void *lpAce = NULL;
	LPWSTR SidString, SidString2;
	wchar_t unknown[256] = L"unknown";

	WCHAR wUser[512];
	DWORD dwUserLen = 0;

	LPTSTR wDomain = NULL;
	DWORD dwDomainLen = 0;
	SID_NAME_USE type_of_SID;


	for (unsigned i = 0; i < lpDacl->AceCount; ++i)
	{
		//получаем указатель на ACE из ACL
		if (!GetAce(
			lpDacl, //адрес DACL
			i, //индекс элемента
			&lpAce))
			//(LPVOID*)&pAce)) //указатель на элемент списка
		{
			dwErrCode = GetLastError();
			printf("Error get ace: %u\n", dwErrCode);
		}


		//SID
		if (!ConvertSidToStringSidW(&((ACCESS_ALLOWED_ACE *)lpAce)->SidStart, &SidString))
		{

			SidString = unknown;
			wcscpy(wUser, unknown);

		}
		else
		{

			//определяем длину имени домена
			if (!LookupAccountSid(
				NULL, //ищем на локальном компе
				&((ACCESS_ALLOWED_ACE *)lpAce)->SidStart, //указатель на SID
				//&pAce->SidStart,
				wUser, //имя пользователя
				&dwUserLen, //длина имени
				wDomain, //имя домена
				&dwDomainLen, //длина имени домена
				//0))
				&type_of_SID)) //тип учетной записи
			{
				dwErrCode = GetLastError();
				if (dwErrCode == ERROR_INSUFFICIENT_BUFFER)
				{
					//распределяем память под имя домена 
					wDomain = (LPTSTR)new wchar_t[dwDomainLen];
				}
				else
				{
					printf("Error lookup domain: %u\n", dwErrCode);
				}
			}

			//определяем имя учетной записи по SID
			if (!LookupAccountSid(
				NULL, //ищем на локальном компе
				&((ACCESS_ALLOWED_ACE *)lpAce)->SidStart, //указатель на SID
				//&pAce->SidStart,
				wUser, //имя пользователя
				&dwUserLen, //длина имени
				wDomain, //имя домена
				&dwDomainLen, //длина имени домена
				//0))
				&type_of_SID)) //тип учетной записи
			{
				dwErrCode = GetLastError();
				//Иногда выдает error, хотя имя определяется
				//printf("Error lookup account: %u\n", dwErrCode);
			}


		}
		//весь вывод
		printf("%i)\n",i);
		//char output[256];
		//sprintf(output, "%ws", wUser);
		//printf("User: %s\n", output);
		printf("User: %ws\n", wUser);
		//wprintf(L"User: %ls\n", wUser);
		printf("User's SID: %ws\n", SidString);

		DisplayPermissions(((ACCESS_ALLOWED_ACE *)lpAce)->Mask);
		printf("ACE type:\n");
		if (((ACCESS_ALLOWED_ACE *)lpAce)->Header.AceType == ACCESS_ALLOWED_ACE_TYPE)
		{
			printf("\tAccess permitted\n");
		}
		else
		{
			printf("\tAccess denied\n");
		}

		//DisplayFlags(((ACCESS_ALLOWED_ACE *)lpAce)->Header);


		printf("-------------------------------------------------------\n\n");

	}
}

//добавление ACE
DWORD Add_Ace(
	LPTSTR pszObjName,          // name of object
	SE_OBJECT_TYPE ObjectType,  // type of object
	LPTSTR pszTrustee,          // trustee for new ACE(имя пользователя к которому применяется запись ACE)
	TRUSTEE_FORM TrusteeForm,   // format of trustee structure(формат = имя)
	DWORD dwAccessRights,       // access mask for new ACE
	ACCESS_MODE AccessMode,     // type of ACE
	DWORD dwInheritance         // inheritance flags for new ACE
)
{
	DWORD dwRes = 0;
	PACL pOldDACL = NULL, pNewDACL = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	EXPLICIT_ACCESS ea;

	if (NULL == pszObjName)
		return ERROR_INVALID_PARAMETER;

	// Get a pointer to the existing DACL.

	dwRes = GetNamedSecurityInfo(pszObjName, ObjectType,
		DACL_SECURITY_INFORMATION,
		NULL, NULL, &pOldDACL, NULL, &pSD);
	if (ERROR_SUCCESS != dwRes) {
		printf("GetNamedSecurityInfo Error %u\n", dwRes);
		goto Cleanup;
	}

	// Initialize an EXPLICIT_ACCESS structure for the new ACE. 

	ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
	ea.grfAccessPermissions = dwAccessRights;
	ea.grfAccessMode = AccessMode;
	ea.grfInheritance = dwInheritance;
	ea.Trustee.TrusteeForm = TrusteeForm;
	ea.Trustee.ptstrName = pszTrustee;

	// Create a new ACL that merges the new ACE
	// into the existing DACL.

	dwRes = SetEntriesInAcl(1, &ea, pOldDACL, &pNewDACL);
	if (ERROR_SUCCESS != dwRes) {
		printf("SetEntriesInAcl Error %u\n", dwRes);
		goto Cleanup;
	}

	// Attach the new ACL as the object's DACL.

	dwRes = SetNamedSecurityInfo(pszObjName, ObjectType,
		DACL_SECURITY_INFORMATION,
		NULL, NULL, pNewDACL, NULL);
	if (ERROR_SUCCESS != dwRes) {
		printf("SetNamedSecurityInfo Error %u\n", dwRes);
		goto Cleanup;
	}
	else
	{
		printf("ACE WAS ADDED!\n\n");
	}

Cleanup:

	if (pSD != NULL)
		LocalFree((HLOCAL)pSD);
	if (pNewDACL != NULL)
		LocalFree((HLOCAL)pNewDACL);

	return dwRes;
}

//удаление ACE
int Delete_Ace(wchar_t * chDirName, int ace_number)
{
	//char chDirName[248];  // имя файла

	PSECURITY_DESCRIPTOR lpSd = NULL;  // указатель на SD

	PACL lpDacl = NULL;    // указатель на список управления доступом
	BOOL bDaclPresent;     // признак присутствия списка DACL
	BOOL bDaclDefaulted;   // признак списка DACL по умолчанию

	void *lpAce = NULL;    // указатель на элемент списка

	DWORD dwLength;        // длина дескриптора безопасности
	DWORD dwRetCode;       // код возврата

	// получаем длину дескриптора безопасности
	if (!GetFileSecurity(
		chDirName,         // имя файла
		DACL_SECURITY_INFORMATION,   // получаем DACL
		lpSd,              // адрес дескриптора безопасности
		0,                 // определяем длину буфера
		&dwLength))        // адрес для требуемой длины
	{
		dwRetCode = GetLastError();

		if (dwRetCode == ERROR_INSUFFICIENT_BUFFER)
			// распределяем память для буфера
			lpSd = (SECURITY_DESCRIPTOR*) new char[dwLength];
		else
		{
			// выходим из программы
			printf("Get file security failed.\n");
			printf("Error code: %d\n", dwRetCode);

			return dwRetCode;
		}
	}

	// распределяем память для дескриптора безопасности
	lpSd = (PSECURITY_DESCRIPTOR) new char[dwLength];

	// читаем дескриптор безопасности
	if (!GetFileSecurity(
		chDirName,     // имя файла
		DACL_SECURITY_INFORMATION,   // получаем DACL
		lpSd,          // адрес дескриптора безопасности
		dwLength,      // длину буфера
		&dwLength))    // адрес для требуемой длины
	{
		dwRetCode = GetLastError();
		printf("Get file security failed.\n");
		printf("Error code: %d\n", dwRetCode);

		return dwRetCode;
	}

	// получаем список DACL из дескриптора безопасности
	if (!GetSecurityDescriptorDacl(
		lpSd,              // адрес дескриптора безопасности
		&bDaclPresent,     // признак присутствия списка DACL
		&lpDacl,           // адрес указателя на DACL
		&bDaclDefaulted))  // признак списка DACL по умолчанию
	{
		dwRetCode = GetLastError();
		printf("Get security descriptor DACL failed.\n");
		printf("Error code: %d\n", dwRetCode);

		return dwRetCode;
	}

	// проверяем, есть ли DACL
	if (!bDaclPresent)
	{
		printf("Dacl is not present.");

		return 0;
	}

	// получить элемент списка DACL
	if (!GetAce(
		lpDacl,    // адрес DACL
		ace_number,         // индекс элемента
		&lpAce))   // указатель на элемент списка
	{
		dwRetCode = GetLastError();
		printf("Get ace failed.\n");
		printf("Error code: %d\n", dwRetCode);

		return dwRetCode;
	}

	//основа
	if (DeleteAce(lpDacl, ace_number) != 0)
		printf("ACE WAS DELETED\n\n");

	if (!SetFileSecurity(
		chDirName,                   // имя файла
		DACL_SECURITY_INFORMATION,   // устанавливаем DACL
		lpSd))                       // адрес дескриптора безопасности
	{
		dwRetCode = GetLastError();
		printf("Set file security failed.\n");
		printf("Error code: %d\n", dwRetCode);

		return dwRetCode;
	}

	// удаляем запрещающие доступ элементы списка DACL
	//for (unsigned i = 0; i < lpDacl->AceCount; ++i)
	//{
	//	// получить элемент списка DACL
	//	if (!GetAce(
	//		lpDacl,    // адрес DACL
	//		i,         // индекс элемента
	//		&lpAce))   // указатель на элемент списка
	//	{
	//		dwRetCode = GetLastError();
	//		printf("Get ace failed.\n");
	//		printf("Error code: %d\n", dwRetCode);
	//		return dwRetCode;
	//	}
	//	// проверяем тип элемента
	//	if (((ACE_HEADER*)lpAce)->AceType == ACCESS_DENIED_ACE_TYPE)
	//		// удаляем элемент из списка DACL
	//		if (!DeleteAce(lpDacl, i))
	//		{
	//			dwRetCode = GetLastError();
	//			printf("Delete ace failed.\n");
	//			printf("Error code: %d\n", dwRetCode);
	//			return dwRetCode;
	//		}
	//}
	//// устанавливаем новый дескриптор безопасности
	//if (!SetFileSecurity(
	//	chDirName,                   // имя файла
	//	DACL_SECURITY_INFORMATION,   // устанавливаем DACL
	//	lpSd))                       // адрес дескриптора безопасности
	//{
	//	dwRetCode = GetLastError();
	//	printf("Set file security failed.\n");
	//	printf("Error code: %d\n", dwRetCode);
	//	return dwRetCode;
	//}



	// освобождаем память
	delete[] lpSd;

	return 0;
}



int Print_Owner(wchar_t* wchDirName)
{
	wchar_t owner[512];
	DWORD dwRtnCode = 0;
	PSID pSidOwner = NULL;
	BOOL bRtnBool = TRUE;
	LPTSTR AcctName = NULL;
	LPTSTR DomainName = NULL;
	DWORD dwAcctName = 1, dwDomainName = 1;
	SID_NAME_USE eUse = SidTypeUnknown;
	HANDLE hFile;
	PSECURITY_DESCRIPTOR pSD = NULL;


	// Get the handle of the file object.
	hFile = CreateFile(
		//TEXT("myfile.txt"),
		wchDirName,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	// Check GetLastError for CreateFile error code.
	if (hFile == INVALID_HANDLE_VALUE)
	{
		DWORD dwErrorCode = 0;

		dwErrorCode = GetLastError();
		printf("CreateFile error = %d\n", dwErrorCode);
		return -1;
	}
	else
	{
		//printf("File was opened\n");
	}


	// Get the owner SID of the file.
	dwRtnCode = GetSecurityInfo(
		hFile,
		SE_FILE_OBJECT,
		OWNER_SECURITY_INFORMATION,
		&pSidOwner,
		NULL,
		NULL,
		NULL,
		&pSD);

	// Check GetLastError for GetSecurityInfo error condition.
	if (dwRtnCode != ERROR_SUCCESS) {
		DWORD dwErrorCode = 0;

		dwErrorCode = GetLastError();
		printf("GetSecurityInfo error = %d\n", dwErrorCode);
		return -1;
	}

	// First call to LookupAccountSid to get the buffer sizes.
	bRtnBool = LookupAccountSid(
		NULL,           // local computer
		pSidOwner,
		AcctName,
		(LPDWORD)&dwAcctName,
		DomainName,
		(LPDWORD)&dwDomainName,
		&eUse);

	// Reallocate memory for the buffers.
	//AcctName = (LPTSTR)GlobalAlloc(
	//	GMEM_FIXED,
	//	dwAcctName);
	AcctName = (wchar_t*)malloc(dwAcctName * sizeof(wchar_t));

	// Check GetLastError for GlobalAlloc error condition.
	if (AcctName == NULL) {
		DWORD dwErrorCode = 0;

		dwErrorCode = GetLastError();
		printf("GlobalAlloc error = %d\n", dwErrorCode);
		free(AcctName);
		return -1;
	}

	//DomainName = (LPTSTR)GlobalAlloc(
	//	GMEM_FIXED,
	//	dwDomainName);
	DomainName = (wchar_t*)malloc(dwDomainName * sizeof(wchar_t));

	// Check GetLastError for GlobalAlloc error condition.
	if (DomainName == NULL) {
		DWORD dwErrorCode = 0;

		dwErrorCode = GetLastError();
		printf("GlobalAlloc error = %d\n", dwErrorCode);
		free(AcctName);
		free(DomainName);
		return -1;

	}

	// Second call to LookupAccountSid to get the account name.
	bRtnBool = LookupAccountSid(
		NULL,                   // name of local or remote computer
		pSidOwner,              // security identifier
		AcctName,               // account name buffer
		(LPDWORD)&dwAcctName,   // size of account name buffer 
		DomainName,             // domain name
		(LPDWORD)&dwDomainName, // size of domain name buffer
		&eUse);                 // SID type

  // Check GetLastError for LookupAccountSid error condition.
	if (bRtnBool == FALSE)
	{
		DWORD dwErrorCode = 0;

		dwErrorCode = GetLastError();

		if (dwErrorCode == ERROR_NONE_MAPPED)
			printf("Account owner not found for specified SID.\n");
		else
			printf("Error in LookupAccountSid.\n");

		free(AcctName);
		free(DomainName);
		return -1;

	}
	else if (bRtnBool == TRUE)
	{
		//ВЫВОД ТУТ
		wcscpy(owner, AcctName);
		printf("Owner: %ws\n\n", owner);
		//wprintf(L"Owner: %ls\n\n", owner);
	}
	CloseHandle(hFile);
	free(AcctName);
	free(DomainName);
	return 0;
}

/*
int Change_Owner(
	wchar_t* wchDirName,    //filename
	wchar_t* wchUserName	//new owner
) {


	DWORD dwSdLength = 0;            // длина SD
	DWORD dwSidLength = 0;           // длина SID
	DWORD dwLengthOfDomainName = 0;  // длина имени домена

	PSID lpSid = NULL;               // указатель на SID нового владельца
	LPTSTR lpDomainName = NULL;      // указатель на имя домена

	SID_NAME_USE typeOfSid;          // тип учетной записи

	SECURITY_DESCRIPTOR sdAbsoluteSd;  // абсолютный формат дескриптора безопасности

	DWORD dwRetCode;     // код возврата

	// определяем длину SID пользователя
	if (!LookupAccountName(
		NULL,            // ищем имя на локальном компьютере
		wchUserName,     // имя пользователя
		NULL,            // определяем длину SID
		&dwSidLength,    // длина SID
		NULL,            // определяем имя домена
		&dwLengthOfDomainName,   // длина имени домена
		&typeOfSid))     // тип учетной записи
	{
		dwRetCode = GetLastError();

		if (dwRetCode == ERROR_INSUFFICIENT_BUFFER)
		{
			// распределяем память для SID
			lpSid = (SID*) new char[dwSidLength];
			lpDomainName = (LPTSTR) new wchar_t[dwLengthOfDomainName];
		}
		else
		{
			// выходим из программы
			printf("Lookup account name length failed.\n");
			printf("Error code: %d\n", dwRetCode);

			return dwRetCode;
		}
	}

	// определяем SID
	if (!LookupAccountName(
		NULL,              // ищем имя на локальном компьютере
		wchUserName,       // имя пользователя
		lpSid,             // указатель на SID
		&dwSidLength,      // длина SID
		lpDomainName,      // указатель на имя домена
		&dwLengthOfDomainName,   // длина имени домена
		&typeOfSid))       // тип учетной записи
	{
		dwRetCode = GetLastError();

		printf("Lookup account name failed.\n");
		printf("Error code: %d\n", dwRetCode);

		return dwRetCode;
	}

	// создаем дескриптор безопасности
	if (!InitializeSecurityDescriptor(
		&sdAbsoluteSd,     // адрес структуры SD
		SECURITY_DESCRIPTOR_REVISION))
	{
		dwRetCode = GetLastError();
		perror("Initialize security descriptor failed.\n");
		printf("The last error code: %u\n", dwRetCode);

		return dwRetCode;
	}

	// устанавливаем нового владельца в дескриптор безопасности

	if (!SetSecurityDescriptorOwner(
		&sdAbsoluteSd,     // адрес дескриптора безопасности
		lpSid,             // указатель на SID
		FALSE))            // SID не задан по умолчанию
	{
		dwRetCode = GetLastError();
		perror("Set security descriptor owner failed.\n");
		printf("The last error code: %u\n", dwRetCode);

		return dwRetCode;
	}

	// проверяем структуру дескриптора безопасности
	if (!IsValidSecurityDescriptor(&sdAbsoluteSd))
	{
		dwRetCode = GetLastError();
		perror("Security descriptor is invalid.\n");
		printf("The last error code: %u\n", dwRetCode);

		return dwRetCode;
	}
	// устанавливаем новый дескриптор безопасности
	if (!SetFileSecurity(
		wchDirName,          // имя файла
		OWNER_SECURITY_INFORMATION,  // устанавливаем SID
		&sdAbsoluteSd))      // адрес дескриптора безопасности
	{
		dwRetCode = GetLastError();

		if (dwRetCode == ERROR_INVALID_OWNER)
			printf("The user can not be the owner of the file.\n");

		printf("Set file security failed.\n");
		printf("Error code: %d\n", dwRetCode);

		return dwRetCode;
	}

	// освобождаем память
	delete[] lpSid;
	delete[] lpDomainName;

	return 0;
}

*/

void Show_Info(wchar_t* wchDirName)
{
	printf("\n");
	Print_Owner(wchDirName);
	printf("Access Control List\n");
	printf("-------------------------------------------------------\n");
	printf("-------------------------------------------------------\n");
	Show_ACL(wchDirName);
}

BOOL DirectoryExists(LPCWSTR szPath)
{
	DWORD dwAttrib = GetFileAttributes(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

bool FileExists(LPCWSTR fileName)
{
	DWORD       fileAttr;

	fileAttr = GetFileAttributes(fileName);
	if (0xFFFFFFFF == fileAttr)
		return false;
	return true;
}

int main()
{
	wchar_t username[512];// = L"Ilya";
	wchar_t wchDirName[512] = L"\0";// = L"C:\\Users\\Ilya\\Desktop\\MBKS\\1.txt";   // имя каталога
	//wchar_t wchDirName[512] = L"C:\\Users\\Public\\1.txt";   // имя каталога
	//wchar_t trustee[512] = L"Gulnara"; //имя доверенного лица
	wchar_t trustee[512];// = L"Ilya"; //имя доверенного лица
	wchar_t new_owner[512];// = L"Administrators";

	//Show_Info(wchDirName);
	
	while (1)
	{
		printf("Enter directory name: ");
		wscanf(L"%ls", wchDirName);
		if (DirectoryExists(wchDirName))
			break;
		else if (FileExists(wchDirName))
			break;
		else
			printf("Directory/File doesn't exist!\n");
	}

	int option, del_ace_num;
	while (1)
	{
		printf("1)Print current directory\n2)Change directory\n3)Show Info\n");
		printf("4)Add ACE\n5)Delete ACE\n6)Exit\n");
		cin >> option;
		if (option == 0)
		{
			wchar_t userrname[128];
			DWORD userrname_len = 128;
			GetUserName(userrname, &userrname_len);
			printf("Current user: %ws\n", userrname);
		}
		if (option == 1)
		{
			wprintf(L"%ls", wchDirName);
			printf("\n");
		}
		if (option == 2)
		{
			while (1)
			{
				printf("Enter new directory name: ");
				wscanf(L"%ls", wchDirName);
				if (DirectoryExists(wchDirName))
					break;
				else if (FileExists(wchDirName))
					break;
				else
					printf("Directory/File doesn't exist!\n");
			}
		}
		if (option == 3)
		{
			Show_Info(wchDirName);
		}
		if (option == 4)
		{
			//ACL для файлв
			//ACE = имя пользователя + SID + permissions(маски) + флаги наследования
			//DWORD mask = GENERIC_WRITE | GENERIC_EXECUTE;
			
			printf("Print trustee:");
			wscanf(L"%ls",trustee);

			DWORD mask = 0x0000000;
			printf("Enter access rights (numbers in a row, without commas):\n");
			printf("1)Generic Read\n2)Generic Write\n3)Generic Execute\n4)Generic All\n");
			char rights_row[32];
			scanf("%s", rights_row);
			if (strchr(rights_row, '4'))
			{
				mask |= GENERIC_ALL;
			}
			if (strchr(rights_row, '1'))
			{
				mask |= GENERIC_READ;
			}
			if (strchr(rights_row, '2'))
			{
				mask |= GENERIC_WRITE;
			}
			if (strchr(rights_row, '3'))
			{
				mask |= GENERIC_EXECUTE;
			}

			Add_Ace(
				wchDirName, //всегда путь к файлу
				SE_FILE_OBJECT, //всегда тип = файл обджект
				trustee, // всегда имя пользователя к которму применяем ACE 
				TRUSTEE_IS_NAME, //всегда тип = имя
				mask, //значение маски(строка 49 DisplayPermissions)
				SET_ACCESS, // DENY_ACCESS or SET_ACCESS
				NO_INHERITANCE); //

			//printf("ACE WAS ADDED!\n\n");
		}
		if (option == 5)
		{
			printf("Enter number of ACE:");
			cin >> del_ace_num;
			Delete_Ace(wchDirName, del_ace_num);
		}
		/*
		if (option == 6)
		{
			printf("Enter new owner:");
			wscanf(L"%ls", new_owner);

			Change_Owner(wchDirName, new_owner);
			
		}*/
		if (option == 6)
		{
			break;
		}
	}
	





	//Show_ACL(wchDirName);

	//Delete_Ace(wchDirName,1);

	//Show_ACL(wchDirName);


	//ВЛАДЕЛЕЦ
	//wchar_t str[512];
	//Print_Owner(wchDirName);
	//scanf("%ws",&str);
	//Change_Owner(wchDirName, str);
	//Print_Owner(wchDirName);




	//


	//_getch();

	return 0;
}