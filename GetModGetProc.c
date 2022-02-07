#include <windows.h>
#include <winternl.h>
#include <stdio.h>

void * GetFunctionAddress(char * MyNtdllFunction, PVOID MyDLLBaseAddress) {

	DWORD j;
	uintptr_t RVA = 0;
	
	//Parse DLL loaded in memory
	const LPVOID BaseDLLAddr = (LPVOID)MyDLLBaseAddress;
	PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER) BaseDLLAddr;
	PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR) BaseDLLAddr + pImgDOSHead->e_lfanew);

    	//Get the Export Directory Structure
	PIMAGE_EXPORT_DIRECTORY pImgExpDir =(PIMAGE_EXPORT_DIRECTORY)((LPBYTE)BaseDLLAddr+pImgNTHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    	//Get the functions RVA array
	PDWORD Address=(PDWORD)((LPBYTE)BaseDLLAddr+pImgExpDir->AddressOfFunctions);

    	//Get the function names array 
	PDWORD Name=(PDWORD)((LPBYTE)BaseDLLAddr+pImgExpDir->AddressOfNames);

    	//get the Ordinal array
	PWORD Ordinal=(PWORD)((LPBYTE)BaseDLLAddr+pImgExpDir->AddressOfNameOrdinals);

	//Get RVA of the function from the export table
	for(j=0;j<pImgExpDir->NumberOfNames;j++){
        	if(!strcmp(MyNtdllFunction,(char*)BaseDLLAddr+Name[j])){
			//if function name found, we retrieve the RVA
         		RVA = (uintptr_t)((LPBYTE)Address[Ordinal[j]]);
			break;
		}
	}
	
    	if(RVA){
		//Compute RVA to find the current address in the process
	    	uintptr_t moduleBase = (uintptr_t)BaseDLLAddr;
	    	uintptr_t* TrueAddress = (uintptr_t*)(moduleBase + RVA);
	    	return (PVOID)TrueAddress;
    	}else{
        	return (PVOID)RVA;
    	}
}


void * DLLViaPEB(wchar_t * DllNameToSearch){

    	PPEB pPeb = 0;
	PLDR_DATA_TABLE_ENTRY pDataTableEntry = 0;
	PVOID DLLAddress = 0;

	//Retrieve from the TEB (Thread Environment Block) the PEB (Process Environment Block) address
    	#ifdef _M_X64
        //If 64 bits architecture
        	PPEB pPEB = (PPEB) __readgsqword(0x60);
    	#else
        //If 32 bits architecture
        	PPEB pPEB = (PPEB) __readfsdword(0x30);
    	#endif

	//Retrieve the PEB_LDR_DATA address
	PPEB_LDR_DATA pLdr = pPEB->Ldr;

	//Address of the First PLIST_ENTRY Structure
    	PLIST_ENTRY AddressFirstPLIST = &pLdr->InMemoryOrderModuleList;

	//Address of the First Module which is always (I think) the current program;
	PLIST_ENTRY AddressFirstNode = AddressFirstPLIST->Flink;

    	//Searching through all module the DLL we want
	for (PLIST_ENTRY Node = AddressFirstNode; Node != AddressFirstPLIST ;Node = Node->Flink) // Node = Node->Flink means we go the next Node !
	{
		// Node is pointing to InMemoryOrderModuleList in the LDR_DATA_TABLE_ENTRY structure.
        	// InMemoryOrderModuleList is at the second position in this structure.
		// To cast in the proper type, we need to go at the start of the structure.
        	// To do so, we need to subtract 1 byte. Indeed, InMemoryOrderModuleList is at 0x008 from the start of the structure) 
		Node = Node - 1;

        	// DataTableEntry structure
		pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)Node;

        	// Retrieve de full DLL Name from the DataTableEntry
        	wchar_t * FullDLLName = (wchar_t *)pDataTableEntry->FullDllName.Buffer;

        	//We lower the full DLL name for comparaison purpose
        	for(int size = wcslen(FullDLLName), cpt = 0; cpt < size ; cpt++){
            		FullDLLName[cpt] = tolower(FullDLLName[cpt]);
        	}

        	// We check if the full DLL name is the one we are searching
        	// If yes, return  the dll base address
        	if(wcsstr(FullDLLName, DllNameToSearch) != NULL){
            		DLLAddress = (PVOID)pDataTableEntry->DllBase;
            		return DLLAddress;
        	}

		// Now, We need to go at the original position (InMemoryOrderModuleList), to be able to retrieve the next Node with ->Flink
		Node = Node + 1;
	}

    	return DLLAddress;
}

int main()
{

	// The DLL you want
    	wchar_t * DllNameToSearch = L"ntdll";
    	// The function you want to find in the Dll set in DllNameToSearch
	char * FunctionNameToSearch = "NtOpenProcess"; 

    	PVOID DLLaddress = DLLViaPEB(DllNameToSearch);
    	if(DLLaddress){
        	printf("\n Here we go the DLL base address of %ls : %x", DllNameToSearch, DLLaddress);
    	}else{
        	printf("\n Address not found :(");
		return -1;
    	}
	
	PVOID FunctionAddress = GetFunctionAddress(FunctionNameToSearch, DLLaddress);
	
	if(FunctionAddress){
		printf("\n Here we go the address of the function %s : %x", FunctionNameToSearch, FunctionAddress);
    	}else{
        	printf("\n %s address not found :(", FunctionNameToSearch);
		return -1;
    	}

}
