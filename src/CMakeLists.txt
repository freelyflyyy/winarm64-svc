set(PROJECT_SOURCES
  "winarm64-svc.cpp"
)

set(PROJECT_ASM
  "direct-svc.asm"
)

set(PROJECT_HEADERS
  "winarm64-svc.h"
  "win-headers.h"
  "nt-structs.h"
  "scope-action.hpp"
)


add_executable(winarm64-svc
  ${PROJECT_SOURCES}
  ${PROJECT_ASM}
  ${PROJECT_HEADERS}
)

source_group("Source Files" FILES ${PROJECT_SOURCES})
source_group("Assembly Files" FILES ${PROJECT_ASM})
source_group("Header Files" FILES ${PROJECT_HEADERS})

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET winarm64-svc PROPERTY CXX_STANDARD 20)
endif()
