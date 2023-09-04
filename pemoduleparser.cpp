#include <iostream>
#include <Windows.h>

int main(int argc, char* argv[])
{
    const int MAX_FILEPATH = 255;
    char filename[MAX_FILEPATH] = {0};
    memcpy_s(&filename, MAX_FILEPATH, argv[1], MAX_FILEPATH);
    HANDLE filehandle = NULL;
    DWORD filesize = NULL;
    DWORD bytesread = NULL;
    LPVOID filedata = NULL;
    PIMAGE_DOS_HEADER dosheader = {};
    PIMAGE_NT_HEADERS ntheader = {};
    PIMAGE_SECTION_HEADER sectionheader = {};
    PIMAGE_SECTION_HEADER importsection = {};
    DWORD rawoffset = NULL;
    IMAGE_IMPORT_DESCRIPTOR* importdescriptor = {};

    filehandle = CreateFileA(filename, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (filehandle == INVALID_HANDLE_VALUE) printf("Could not read file");

    filesize = GetFileSize(filehandle, NULL);
    filedata = HeapAlloc(GetProcessHeap(), 0, filesize);

    ReadFile(filehandle, filedata, filesize, &bytesread, NULL);

    dosheader = (PIMAGE_DOS_HEADER)filedata;
    printf("\t0x%x\t\tMagic number\n", dosheader->e_magic);

    ntheader = (PIMAGE_NT_HEADERS)((DWORD)filedata + dosheader->e_lfanew);

    DWORD sectionlocation = (DWORD)ntheader + sizeof(DWORD) + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)ntheader->FileHeader.SizeOfOptionalHeader;
    DWORD sectionsize = (DWORD)sizeof(IMAGE_SECTION_HEADER);

    DWORD importDirectoryRVA = ntheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    for (int i = 0; i < ntheader->FileHeader.NumberOfSections; i++) {
        sectionheader = (PIMAGE_SECTION_HEADER)sectionlocation;
        printf("\t%s\n", sectionheader->Name);
        if (importDirectoryRVA >= sectionheader->VirtualAddress && importDirectoryRVA < sectionheader->VirtualAddress + sectionheader->Misc.VirtualSize) {
            importsection = sectionheader;
            
        }
        sectionlocation += sectionsize;
    }
    printf("\t%s\n", importsection->Name);
    rawoffset = (DWORD)filedata + importsection->PointerToRawData;

    importdescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(rawoffset + ((ntheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) - importsection->VirtualAddress));

    for (; importdescriptor->Name != 0; importdescriptor++) {
        printf("\t%s\n", rawoffset + (importdescriptor->Name - importsection->VirtualAddress));
    }

    return 0;
    
}
