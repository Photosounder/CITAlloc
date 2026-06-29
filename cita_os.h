// Header part
#ifndef H_CITA_OS
#define H_CITA_OS

  #if defined(__wasm__)
    #define CITA_OS_WASM
  #elif defined(_WIN32)
    #define CITA_OS_WINDOWS
  #elif defined(__APPLE__) && defined(__MACH__)
    #define CITA_OS_MAC
  #else
    #error cita_os.h only supports Windows, macOS and WebAssembly
  #endif

  #ifdef CITA_OS_WASM
    #if defined(CITA_OS_IMPLEMENTATION_PART1) && !defined(CITA_WASM_IMPLEMENTATION_PART1)
      #define CITA_WASM_IMPLEMENTATION_PART1
    #endif
    #if defined(CITA_OS_IMPLEMENTATION) && !defined(CITA_WASM_IMPLEMENTATION_PART2)
      #define CITA_WASM_IMPLEMENTATION_PART2
    #endif
    #include "cita_wasm.h"
  #endif

  #ifdef CITA_OS_WINDOWS
    #if defined(CITA_OS_IMPLEMENTATION) && !defined(CITA_WIN_IMPLEMENTATION)
      #define CITA_WIN_IMPLEMENTATION
    #endif
    #if defined(CITA_OS_MAX) && !defined(CITA_WIN_MAX)
      #define CITA_WIN_MAX CITA_OS_MAX
    #endif
    #include "cita_windows.h"
  #endif

  #ifdef CITA_OS_MAC
    #if defined(CITA_OS_IMPLEMENTATION) && !defined(CITA_MAC_IMPLEMENTATION)
      #define CITA_MAC_IMPLEMENTATION
    #endif
    #if defined(CITA_OS_MAX) && !defined(CITA_MAC_MAX)
      #define CITA_MAC_MAX CITA_OS_MAX
    #endif
    #include "cita_mac.h"
  #endif

#endif // H_CITA_OS
