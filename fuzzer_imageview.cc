// Nero - October 6 2024
#include "backend.h"
#include "targets.h"
#include "handle_table.h"
#include "crash_detection_umode.h"
#include "fshandle_table.h"
#include <fmt/format.h>

namespace fs = std::filesystem;

#define MAX_INPUT_LEN 5117

//
// It is recommended to grab a snapshot with the biggest InputBufferLength
// possible.
//

namespace Imageview {

constexpr bool LoggingOn = false;

template <typename... Args_t>
void DebugPrint(const char *Format, const Args_t &...args) {
  if constexpr (LoggingOn) {
    fmt::print("Imageview: ");
    fmt::print(fmt::runtime(Format), args...);
  }
}

bool InsertTestcase(const uint8_t *Buffer, const size_t BufferSize) 
{
    // Check length doesn't exceed max
    if (BufferSize < 108) 
    {
        return true;
    }

    if (BufferSize > MAX_INPUT_LEN) {
      return false;
    }

    /*struct ImageInfo 
    {
      uint8_t padding[0x130]; // offset 0x0
      void *blob;           // offset 0x130
      size_t length;        // offset 0x138
      char magic[8];        // offset 0x140
    };*/

    size_t BufferSz = BufferSize;

    // fimage!FImageDraw::SetFillColor+0x1e9aa0

    const Gva_t ImageInfoPtr = (const Gva_t)g_Backend->GetReg(Registers_t::Rcx);
    const Gva_t BlobPtr = g_Backend->VirtReadGva(ImageInfoPtr + Gva_t(0x130));
    const size_t Length = g_Backend->VirtRead8(ImageInfoPtr + Gva_t(0x138));

    //DebugPrint("ImageInfoPtr: {:#x}\n", ImageInfoPtr); // 0x2665B6FEE70
    //DebugPrint("BlobPtr: {:#x}\n", BlobPtr);           // 0x2665b65ac00
    //DebugPrint("Length: {:#x}\n", Length);             // 0x13fd

    // Clear the buffer
    std::vector<uint8_t> ZeroBuffer(MAX_INPUT_LEN, 0);

    if (!g_Backend->VirtWriteDirty(BlobPtr, ZeroBuffer.data(), MAX_INPUT_LEN)) {
      DebugPrint("VirtWriteDirty1 failed\n");
    }

    // Write input buffer contents
    if (!g_Backend->VirtWriteDirty(BlobPtr, Buffer, BufferSz)) {
      DebugPrint("VirtWriteDirty1 failed\n");
    }

    // Write input buffer size
    if (!g_Backend->VirtWriteDirty(ImageInfoPtr + Gva_t(0x138),
                                   (const uint8_t *)&BufferSz,
                                   sizeof(uint32_t))) {
      DebugPrint("VirtWriteDirty2 failed\n");
    }

    // We took snapshot at the beginning of the function FImage::Load(img_obj, bufferPtr, bufferSz)

    // Pointer to the input buffer
    /* const Gva_t BufferPtr =
        (const Gva_t)g_Backend->GetReg(Registers_t::Rdx);
    
    const Gva_t BufferSizePtr = (const Gva_t)0x000000736c17fd58;
    size_t BufferSz = BufferSize;

    // Write input buffer contents
    if (!g_Backend->VirtWriteDirty(BufferPtr, Buffer, BufferSz)) {
      DebugPrint("VirtWriteDirty1 failed\n");
      return false;
    }

    if (!g_Backend->SetReg(Registers_t::R8, BufferSz))
    {
      DebugPrint("SetReg failed\n");
      return false;
    }

    // Write input buffer size
    /* if (!g_Backend->VirtWriteDirty(
                 BufferSizePtr, (const uint8_t *)&BufferSz,
                                   sizeof(uint32_t))) {
      DebugPrint("VirtWriteDirty2 failed\n");
      return false;
    }*/

    DebugPrint("Inserted testcase of size {}\n", BufferSz);

    //uint64_t lastCR3 = g_Backend->GetReg(Registers_t::Cr3);

    //DebugPrint("lastCR3: {:#x}\n", lastCR3);

    return true;
}

bool Init(const Options_t &Opts, const CpuState_t &CpuState) {

  //
  // Stop the test-case once we return back from the call FImage::Load()
  //
  // 00007ffe`714400fe c3                 ret
  /*const Gva_t AfterCall = (Gva_t)0x7ff63d2013e7;
  if (!g_Backend->SetBreakpoint(AfterCall, [](Backend_t *Backend) {
        // Get the value of AL (lower 8 bits of RAX)
        uint64_t rax = Backend->GetReg(Registers_t::Rax);
        uint8_t al = rax & 0xFF;

        //DebugPrint("FImage::Load returned: {:#x}\n", al);
        Backend->Stop(Ok_t());
      })) {
    return false;
  }*/

  //
  // Make ExGenRandom deterministic.
  //
  // u nt!ExGenRandom+0xfb L2
  // nt!ExGenRandom+0xfb: 
  // fffff807`7985073b 0fc7f2 rdrand edx
  // fffff807`7985073e b800000000 mov eax, 0
  //

  const Gva_t ExGenRandom = Gva_t(g_Dbg->GetSymbol("nt!ExGenRandom") + 0xfb);
  if (g_Backend->VirtRead4(ExGenRandom) != 0xb8f2c70f) {
    DebugPrint("It seems that nt!ExGenRandom's code has changed, update the offset!\n");
    return false;
  }

  if (!g_Backend->SetBreakpoint(ExGenRandom, [](Backend_t *Backend) {
        //DebugPrint("Hit ExGenRandom!\n");
        uint32_t Rdrand = (uint32_t)Backend->Rdrand();
        Backend->Rdx(Rdrand);
      })) {
    return false;
  }

  //
  // ImageMagick JPEG parsing function READJPEG
  //
  /*
    fimage!FImageDraw::SetFillColor+0x1e9aa0:
    00007ffe`7162c680 4881ec98020000  sub     rsp,298h
    00007ffe`7162c687 488b056a279b00  mov     rax,qword ptr [fimage!FImageProgressMonitor::`vftable'+0x3ac6c8 (00007ffe`71fdedf8)]
    00007ffe`7162c68e 4833c4          xor     rax,rsp
    00007ffe`7162c691 4889842480020000 mov     qword ptr [rsp+280h],rax
    00007ffe`7162c699 4c8bc2          mov     r8,rdx
    00007ffe`7162c69c 488d542420      lea     rdx,[rsp+20h]
    00007ffe`7162c6a1 e81a000000      call    fimage!FImageDraw::SetFillColor+0x1e9ae0 (00007ffe`7162c6c0)
    00007ffe`7162c6a6 488b8c2480020000 mov     rcx,qword ptr [rsp+280h]
  */
  const Gva_t READJPEG = (Gva_t)0x7ffe2cebc6bd;
  if (!g_Backend->SetBreakpoint(READJPEG, [](Backend_t *Backend) {
        DebugPrint("READJPEG ret hit!\n");
        Backend->Stop(Ok_t());
      })) {
    return false;
  }

  //
  // By setting a breakpoint on CreateFileW and simulating ERROR_PATH_NOT_FOUND we lower the coverage by 40% and we also decrease the number of CR3 changes.
  //
  
  if (!g_Backend->SetBreakpoint(
               "kernel32!CreateFileW", [](Backend_t *Backend) {
        //HANDLE CreateFileW(
        //    [in] LPCWSTR lpFileName, 
        //    [in] DWORD dwDesiredAccess,
        //    [in] DWORD dwShareMode,
        //    [ in, optional ] LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        //    [in] DWORD dwCreationDisposition, 
        //    [in] DWORD dwFlagsAndAttributes,
        //    [ in, optional ] HANDLE hTemplateFile);

        const Gva_t lpFileNamePtr = Backend->GetArgGva(0);

        // Read the file name (wide string) from the guest's memory
        std::u16string fileName = Backend->VirtReadWideString(lpFileNamePtr);

        // Convert to UTF-8 for printing (optional)
        std::string fileNameUtf8 = u16stringToString(fileName);

        std::string lookup[] = {"JPEG:", "delegates.xml", "configure.c", "jpeg.c"};

        DebugPrint("CreateFileW called with filename: {}\n", fileNameUtf8);
        
        for (const auto &str : lookup) {
          if (fileNameUtf8.find(str) != std::string::npos) {
            Backend->SimulateReturnFromFunction(ERROR_FILE_NOT_FOUND);
          }
        }

      })) {
    return false;
  }

  /* if (!g_Backend->SetBreakpoint(
               "advapi32!RegOpenKeyExAStub", [](Backend_t *Backend) {
        // LONG RegOpenKeyExA(
        //     [in] HKEY hKey,
        //     [in] LPCSTR lpSubKey,
        //     [in] DWORD ulOptions,
        //     [in] REGSAM samDesired,
        //     [out] PHKEY phkResult);

        const Gva_t lpSubKeyPtr = Backend->GetArgGva(1);

        // Read the subkey from the guest's memory
        std::string subKey = Backend->VirtReadString(lpSubKeyPtr);

        DebugPrint("RegOpenKeyExA called with subkey: {}\n", subKey);

        //Backend->Stop(Ok_t());

        Backend->SimulateReturnFromFunction(ERROR_FILE_NOT_FOUND);
      })) {
    return false;
  }*/


  // Catch c++ exceptions thrown by wevtsvc, these would be DoS (potentially, but they may also be handled).
  if (!g_Backend->SetBreakpoint(
               "ucrtbase!CxxThrowException",
               [](Backend_t *Backend) 
      { 
          DebugPrint("ucrtbase!CxxThrowException was hit!\n");
          Backend->Stop(Ok_t());
      })) {
    //DebugPrint("Failed to SetBreakpoint at ucrtbase!CxxThrowException\n");
    return false;
  }

  SetupUsermodeCrashDetectionHooks();
  DebugPrint("Done init\n");
  return true;
}

//
// Restore the original state of the fuzzer.
//
bool Restore() {
  //g_HandleTable.Restore();
  //DebugPrint("Restored snapshot!\n");
  return true;
}

//
// Register the target.
//

Target_t Imageview("imageview", Init, InsertTestcase, Restore);

} // namespace Imageview