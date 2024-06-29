// inMemory.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <stdio.h>
#include <windows.h>
#include "helper.h"
#include "resource.h"
#include "alternative.h"

typedef int (*MainFunctionType)(int argc, char** argv);

typedef struct BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;


typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;




int main(int argc, char* argv[])
{
     
    HRSRC hRsrc = NULL;
    HGLOBAL hGlobal = NULL;
    UINT64* payloadAddress = NULL;
    UINT64 payloadSize = NULL;
    UINT64* inMemory = {0};
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_SECTION_HEADER sec;

    
    hRsrc = FindResourceA(NULL, MAKEINTRESOURCEA(IDR_RCDATA1), MAKEINTRESOURCEA(10));
    if (hRsrc == NULL) {
        PRINTA("find resource API failed\n");
        return 1;
    }

    hGlobal = LoadResource(NULL, hRsrc);
    if (hGlobal == NULL) {
        PRINTA("load resource function failed\n");
        return 1;
    }


    payloadAddress = (UINT64*)LockResource(hGlobal);
    if (payloadAddress == NULL) {
        PRINTA("error in getting payload address\n");
        return 1;
    }

    payloadSize = SizeofResource(NULL, hRsrc);


   
    dos = (PIMAGE_DOS_HEADER)payloadAddress;
    if (dos->e_magic != 23117) {
        PRINTA("Invalid file");
        return 1;
    }

    nt = (PIMAGE_NT_HEADERS)((UINT64)payloadAddress + (UINT64)dos->e_lfanew);
   

    if (nt->OptionalHeader.Magic != 0x020B) {
        PRINTA("This is not a 64-bit PE file");
        return 1;
    }

    //inMemory = (UINT64*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nt->OptionalHeader.SizeOfImage);
    inMemory = VirtualAlloc(NULL, nt->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);



    DWORD_PTR deltaImageBase = (DWORD_PTR)inMemory - (DWORD_PTR)nt->OptionalHeader.ImageBase;

    //copying all the headers
    al_memcpy(inMemory, payloadAddress, nt->OptionalHeader.SizeOfHeaders);


    sec = IMAGE_FIRST_SECTION(nt);
    //copying all the section
    for (size_t i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
       
        LPVOID sectionDestination = (LPVOID)((DWORD_PTR)inMemory + (DWORD_PTR)sec->VirtualAddress);
        LPVOID sectionBytes = (LPVOID)((DWORD_PTR)payloadAddress + (DWORD_PTR)sec->PointerToRawData);
        al_memcpy(sectionDestination, sectionBytes, sec->SizeOfRawData);
        //if (!lstrcmpA(sec->Name, ".text")) {
        //    PDWORD oldprotect = NULL;
        //    //ret = VirtualProtect(inMemory, sec->SizeOfRawData, PAGE_EXECUTE_READWRITE, oldprotect);
        //    /*ret = VirtualProtect(inMemory, nt->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE, oldprotect);
        //    if (!ret) {
        //        printf("last error: %d\n", GetLastError());
        //        PRINTA("Failed to change protection\n")
        //    }*/
        //}
        sec++;
    }
    

    // perform image base relocations
    IMAGE_DATA_DIRECTORY relocations = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    DWORD_PTR relocationTable = relocations.VirtualAddress + (DWORD_PTR)inMemory;
    DWORD relocationsProcessed = 0;

    while (relocationsProcessed < relocations.Size)
    {
        PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)(relocationTable + relocationsProcessed);
        relocationsProcessed += sizeof(BASE_RELOCATION_BLOCK);
        DWORD relocationsCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
        PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)(relocationTable + relocationsProcessed);

        for (DWORD i = 0; i < relocationsCount; i++)
        {
            relocationsProcessed += sizeof(BASE_RELOCATION_ENTRY);

            if (relocationEntries[i].Type == 0)
            {
                continue;
            }

            DWORD_PTR relocationRVA = relocationBlock->PageAddress + relocationEntries[i].Offset;
            DWORD_PTR addressToPatch = 0;
            ReadProcessMemory(GetCurrentProcess(), (LPCVOID)((DWORD_PTR)inMemory + relocationRVA), &addressToPatch, sizeof(DWORD_PTR), NULL);
            addressToPatch += deltaImageBase;
            al_memcpy((PVOID)((DWORD_PTR)inMemory + relocationRVA), &addressToPatch, sizeof(DWORD_PTR));
        }
    }
   

    // resolve import address table
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
    IMAGE_DATA_DIRECTORY importsDirectory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)inMemory);
    LPCSTR libraryName = "";
    HMODULE library = NULL;

    while (importDescriptor->Name != NULL)
    {
        libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)inMemory;
        library = LoadLibraryA(libraryName);

        if (library)
        {
            PIMAGE_THUNK_DATA thunk = NULL;
            thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)inMemory + importDescriptor->FirstThunk);

            while (thunk->u1.AddressOfData != NULL)
            {
                if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
                {
                    LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
                    thunk->u1.Function = (DWORD_PTR)GetProcAddress(library, functionOrdinal);
                }
                else
                {
                    PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)inMemory + thunk->u1.AddressOfData);
                    DWORD_PTR functionAddress = (DWORD_PTR)GetProcAddress(library, functionName->Name);
                    thunk->u1.Function = functionAddress;
                }
                ++thunk;
            }
        }

        importDescriptor++;
    }
   
    MainFunctionType MainEntry = (void*)((DWORD_PTR)inMemory + nt->OptionalHeader.AddressOfEntryPoint);
    UINT64** al_argv = NULL;
    al_argv = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (argc - 1)*8);
    
    al_argv[0] = argv[1];
    al_argv[1] = argv[2];
    al_argv[2] = argv[3];
    al_argv[3] = argv[4];
    al_argv[4] = argv[5];
   
    (*MainEntry)((argc - 1), al_argv);

    //HANDLE loda = LoadLibraryA("api-ms-win-core-com-l1-1-0.dll");
    

    return 0;

}




// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
