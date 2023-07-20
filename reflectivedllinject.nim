import winim, strutils, tables, windows

type
  BaseRelocationBlock = object
    pageAddress: DWORD
    blockSize: DWORD

  BaseRelocationEntry = object
    offset: ushort
    type: ushort

type
  DLLEntry = proc(dll: HINSTANCE, reason: DWORD, reserved: LPVOID): BOOL
  PDLLEntry = ptr DLLEntry

proc loadDLLIntoMemory(filePath: string): seq[byte] =
  let file = open(filePath, fmOpenRead)
  let fileSize = file.size
  result = file.readBytes(fileSize)
  file.close()

proc resolveImportAddressTable(dllBase: LPVOID, importsDirectory: IMAGE_DATA_DIRECTORY): bool =
  var importDescriptor: PIMAGE_IMPORT_DESCRIPTOR
  importDescriptor = cast[PIMAGE_IMPORT_DESCRIPTOR](importsDirectory.VirtualAddress + cast[DWORD_PTR](dllBase))
  var libraryName: LPCSTR
  var library: HMODULE

  while importDescriptor.name != 0:
    libraryName = cast[LPCSTR](importDescriptor.name + cast[DWORD_PTR](dllBase))
    library = LoadLibraryA(libraryName)
    
    if library != nil:
      var thunk: PIMAGE_THUNK_DATA
      thunk = cast[PIMAGE_THUNK_DATA](dllBase + importDescriptor.firstThunk)

      while thunk.u1.addressOfData != 0:
        if thunk.u1.addressOfData and IMAGE_ORDINAL_FLAG != 0:
          let functionOrdinal = cast[LPCSTR](IMAGE_ORDINAL(thunk.u1.addressOfData))
          thunk.u1.function = cast[DWORD_PTR](GetProcAddress(library, functionOrdinal))
        else:
          let functionName = cast[PIMAGE_IMPORT_BY_NAME](dllBase + thunk.u1.addressOfData)
          let functionAddress = cast[DWORD_PTR](GetProcAddress(library, cast[LPCSTR](functionName.name)))
          thunk.u1.function = functionAddress

        inc thunk

    inc importDescriptor

proc executeDLL(dllBase: LPVOID, entryPoint: DWORD_PTR): BOOL =
  let dllEntry = cast[PDLLEntry](dllBase + entryPoint)
  result = dllEntry(HINSTANCE(dllBase), DLL_PROCESS_ATTACH, nil)

proc main() =
  # Get the current module's image base address
  var imageBase: LPVOID
  getCurrentModuleHandleA(imageBase)
  
  # Load the DLL into memory
  let filePath = "\\\\VBOXSVR\\Experiments\\MLLoader\\MLLoader\\x64\\Debug\\dll.dll"
  let dllBytes = loadDLLIntoMemory(filePath)
  
  # Get pointers to in-memory DLL headers
  let dosHeaders = cast[PIMAGE_DOS_HEADER](dllBytes.addr)
  let ntHeaders = cast[PIMAGE_NT_HEADERS](dllBytes.addr + dosHeaders.e_lfanew)
  let dllImageSize = ntHeaders.optionalHeader.sizeOfImage
  
  # Allocate new memory space for the DLL.
  # Try to allocate memory in the image's preferred base address, but don't stress if the memory is allocated elsewhere
  var dllBase: LPVOID
  try:
    dllBase = VirtualAlloc(LPVOID(ntHeaders.optionalHeader.imageBase), dllImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)
  except:
    dllBase = VirtualAlloc(nil, dllImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)

  # Get the delta between this module's image base and the DLL that was read into memory
  let deltaImageBase = cast[DWORD_PTR](dllBase) - cast[DWORD_PTR](ntHeaders.optionalHeader.imageBase)

  # Copy over DLL image headers to the newly allocated space for the DLL
  memcpy(dllBase, dllBytes.addr, ntHeaders.optionalHeader.sizeOfHeaders)

  # Copy over DLL image sections to the newly allocated space for the DLL
  var section = IMAGE_FIRST_SECTION(ntHeaders)
  for i in 0 .. <ntHeaders.fileHeader.numberOfSections:
    let sectionDestination = cast[LPVOID](cast[DWORD_PTR](dllBase) + section.virtualAddress)
    let sectionBytes = cast[LPVOID](cast[DWORD_PTR](dllBytes.addr) + section.pointerToRawData)
    memcpy(sectionDestination, sectionBytes, section.sizeOfRawData)
    inc section

  # Perform image base relocations
  let relocations = ntHeaders.optionalHeader.dataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
  var relocationTable = relocations.virtualAddress + cast[DWORD_PTR](dllBase)
  var relocationsProcessed: DWORD = 0

  while relocationsProcessed < relocations.size:
    let relocationBlock = cast[PBaseRelocationBlock](relocationTable + relocationsProcessed)
    relocationsProcessed += sizeof(BaseRelocationBlock)
    let relocationsCount = (relocationBlock.blockSize - sizeof(BaseRelocationBlock)) div sizeof(BaseRelocationEntry)
    let relocationEntries = cast[PBaseRelocationEntry](relocationTable + relocationsProcessed)

    for i in 0 .. <relocationsCount:
      relocationsProcessed += sizeof(BaseRelocationEntry)

      if relocationEntries[i].type == 0:
        continue

      let relocationRVA = relocationBlock.pageAddress + relocationEntries[i].offset
      var addressToPatch: DWORD_PTR = 0
      ReadProcessMemory(GetCurrentProcess(), LPCVOID(cast[DWORD_PTR](dllBase) + relocationRVA), addressToPatch.addr, sizeof(DWORD_PTR), nil)
      addressToPatch += deltaImageBase
      memcpy(PVOID(cast[DWORD_PTR](dllBase) + relocationRVA), addressToPatch.addr, sizeof(DWORD_PTR))

  # Resolve the import address table
  let importsDirectory = ntHeaders.optionalHeader.dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
  resolveImportAddressTable(dllBase, importsDirectory)

  # Execute the loaded DLL
  let dllEntryPoint = ntHeaders.optionalHeader.addressOfEntryPoint
  executeDLL(dllBase, dllEntryPoint)

when isMainModule:
  main()
