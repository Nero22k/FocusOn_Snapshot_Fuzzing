#include <iostream>
#include <windows.h>

#define MAX_FILE_SIZE 1024 * 55 // 55 KB

// -------------------------------------------------------------------------------------
// fimage.dll functions
// FImage::Load(this, fPath, arg3, arg4)
/*typedef bool(__fastcall* _FImageLoad)(
    char* _this,
    const wchar_t* fPath,
    int64_t arg3,
    uint64_t arg4
    );*/
// In memory function
typedef bool(__fastcall* _FImageLoad)(
    char* _this,
    void* SrcBuffer,
    size_t Length
    );

// FImage::FImage(this)
typedef void* (__fastcall* _FImageConstructor)(
    char* _this
    );

// FImage::~FImage(this)
typedef void (__fastcall* _FImageDestructor)(
    char* _this
    );

// -------------------------------------- Globals --------------------------------------

// Our handle to the target DLL we load in `init()`
// This handle is also the base address of the loaded DLL
HMODULE hMod;

_FImageConstructor FImageConstructor;
_FImageLoad FImageLoad;
_FImageDestructor FImageDestructor;

char* image_obj; // The object we will be fuzzing
char* gBuffer;  // Buffer to store the file contents
int gBufferSize; // Size of the file buffer
uint32_t sample_size; // Size of the file

void test_load_buffer(wchar_t* fPath) {
    // Load file from hardcoded location
    HANDLE hFile = CreateFileW(
        fPath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open the file!, gle=%d\n", GetLastError());
        exit(1);
    }
    LARGE_INTEGER totalSize = {};
    BOOL res = GetFileSizeEx(hFile, &totalSize);
    if (!res) {
        printf("GetFileSizeEx, gle=%d\n", GetLastError());
        exit(2);
    }
    DWORD bRet = 0;
    sample_size = totalSize.QuadPart;
    unsigned char* sample_bytes = (unsigned char*)calloc(1, totalSize.QuadPart);
    res = ReadFile(hFile, sample_bytes, totalSize.QuadPart, &bRet, NULL);
    if (!res) {
        printf("ReadFile failed!, gle=%d\n", GetLastError());
        exit(3);
    }
    if (bRet != totalSize.QuadPart) {
        printf("Read:%d bytes, expected:%d bytes\n", bRet, totalSize.QuadPart);
    }

    if (hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
    }

    // Copy the file contents to the global buffer
    memcpy(gBuffer, sample_bytes, sample_size);
    return;
}

// Function to load and resolve the functions from fimage.dll
void init() 
{
    // Load our target DLL, this will be our main fuzz target
    hMod = LoadLibraryW(L"C:\\Program Files\\Pintosoft\\FocusOn Image Viewer\\fimage.dll");
    if (hMod == 0) {
        printf("Error loading DLL, gle=%d\n", GetLastError());
        exit(1);
    }

    // Resolve the function addresses by ordinal
    FImageConstructor = (_FImageConstructor)GetProcAddress(hMod, MAKEINTRESOURCEA(14));
    //FImageLoad = (_FImageLoad)GetProcAddress(hMod, MAKEINTRESOURCEA(169)); // From disk
    FImageLoad = (_FImageLoad)GetProcAddress(hMod, MAKEINTRESOURCEA(168)); // In memory
    FImageDestructor = (_FImageDestructor)GetProcAddress(hMod, MAKEINTRESOURCEA(23));

    if (FImageConstructor == NULL || FImageLoad == NULL || FImageDestructor == NULL) {
        printf("Error resolving functions, gle=%d\n", GetLastError());
        exit(1);
    }

    // Allocate memory for the image object that we reversed
    image_obj = (char*)calloc(1, 0x40);
    if (!image_obj) {
        printf("Memory allocation failed\n");
        exit(1);
    }

    // Call the constructor function
    FImageConstructor(image_obj);

    gBufferSize = MAX_FILE_SIZE;
    gBuffer = (char*)calloc(1, gBufferSize);
}

// DLL export function that will be called by the fuzzer
#pragma optimize( "", off )
extern "C" __declspec(dllexport) void fuzz() 
{
    try {
        // Load the image file (This is the function we want to fuzz)
        //DebugBreak();
        bool res = FImageLoad(image_obj, gBuffer, sample_size);
        // 1 = success, 0 = failure
        //printf("FImageLoad returned: %d\n", res);
    }
    catch (...) {
        return;
    }
    return;
}
#pragma optimize( "", on )

// The entry point when the harness is run manually or tested outside of WinAFL
int wmain(int argc, wchar_t* argv[]) 
{
    // Initialize the harness and load the target DLL
    init();

    test_load_buffer((wchar_t*)argv[1]);

    // Call the fuzz iteration function manually
    DebugBreak();
    fuzz();

    return 0;
}
