import winim
import strutils

proc main() =
    var functionAddress: ptr uint
    functionAddress = cast[ptr uint](0)
    
    # Get ntdll base address
    var libraryBase: HMODULE = loadLibraryA("ntdll")
    
    var dosHeader: ptr IMAGE_DOS_HEADER = cast[ptr IMAGE_DOS_HEADER](libraryBase)
    var imageNTHeaders: ptr IMAGE_NT_HEADERS = cast[ptr IMAGE_NT_HEADERS](cast[ptr byte](libraryBase) + dosHeader.e_lfanew)
    
    # Locate export address table
    var exportDirectoryRVA: DWORD = imageNTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    var imageExportDirectory: ptr IMAGE_EXPORT_DIRECTORY = cast[ptr IMAGE_EXPORT_DIRECTORY](cast[ptr byte](libraryBase) + exportDirectoryRVA)
    
    # Offsets to list of exported functions and their names
    var addressOfFunctionsRVA: ptr DWORD = cast[ptr DWORD](cast[ptr byte](libraryBase) + imageExportDirectory.AddressOfFunctions)
    var addressOfNamesRVA: ptr DWORD = cast[ptr DWORD](cast[ptr byte](libraryBase) + imageExportDirectory.AddressOfNames)
    var addressOfNameOrdinalsRVA: ptr WORD = cast[ptr WORD](cast[ptr byte](libraryBase) + imageExportDirectory.AddressOfNameOrdinals)
    
    # Iterate through exported functions of ntdll
    for i in 0 ..< imageExportDirectory.NumberOfNames:
        # Resolve exported function name
        var functionNameRVA: DWORD = addressOfNamesRVA[i]
        var functionNameVA: ptr byte = cast[ptr byte](libraryBase) + functionNameRVA
        var functionName: string = cast[cstring](functionNameVA)
        
        # Resolve exported function address
        var functionAddressRVA: DWORD = addressOfFunctionsRVA[addressOfNameOrdinalsRVA[i]]
        functionAddress = cast[ptr uint](cast[ptr byte](libraryBase) + functionAddressRVA)
        
        # Syscall stubs start with these bytes
        const syscallPrologue: array[4, byte] = [0x4c, 0x8b, 0xd1, 0xb8]
        
        # Only interested in Nt|Zw functions
        if functionName.startsWith("Nt") or functionName.startsWith("Zw"):
            # Check if the first 4 instructions of the exported function are the same as the sycall's prologue
            if functionAddress[0..4].addr != syscallPrologue.addr:
                if functionAddress[0] == 0xE9: # first byte is a jmp instruction, where does it jump to?
                    let jumpTargetRelative: DWORD = cast[ptr DWORD](cast[ptr byte](functionAddress) + 1)^
                    var jumpTarget: ptr uint = functionAddress + 5 + jumpTargetRelative
                    var moduleNameBuffer: array[512, char]
                    getMappedFileNameA(getCurrentProcess(), jumpTarget, moduleNameBuffer, 512)
                    echo("Hooked: ", functionName, " : ", functionAddress, " into module ", moduleNameBuffer)
                else:
                    echo("Potentially hooked: ", functionName, " : ", functionAddress)
