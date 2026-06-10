// Header part
#ifndef H_CITA_OS
#define H_CITA_OS

  #if defined(CITA_OS_WINDOWS) && defined(CITA_OS_MAC)
    #error Define only one CITA_OS_* platform selector
  #endif

  #if !defined(CITA_OS_WINDOWS) && !defined(CITA_OS_MAC)
    #if defined(_WIN32)
      #define CITA_OS_WINDOWS
    #elif defined(__APPLE__) && defined(__MACH__)
      #define CITA_OS_MAC
    #else
      #error cita_os.h only supports Windows and macOS
    #endif
  #endif

  #ifdef CITA_OS_WINDOWS
    #ifdef CITA_OS_IMPLEMENTATION
      #ifndef CITA_WIN_IMPLEMENTATION
        #define CITA_WIN_IMPLEMENTATION
      #endif
    #endif
    #ifdef CITA_OS_MAX
      #ifndef CITA_WIN_MAX
        #define CITA_WIN_MAX CITA_OS_MAX
      #endif
    #endif
    #include "cita_windows.h"
  #endif

  #ifdef CITA_OS_MAC
    #ifdef CITA_OS_IMPLEMENTATION
      #ifndef CITA_MAC_IMPLEMENTATION
        #define CITA_MAC_IMPLEMENTATION
      #endif
    #endif
    #ifdef CITA_OS_MAX
      #ifndef CITA_MAC_MAX
        #define CITA_MAC_MAX CITA_OS_MAX
      #endif
    #endif
    #include "cita_mac.h"
  #endif

#endif // H_CITA_OS
