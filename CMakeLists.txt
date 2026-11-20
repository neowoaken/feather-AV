cmake_minimum_required(VERSION 3.20)
project(feather VERSION 0.3.2 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
  add_compile_options(/W4 /utf-8 /permissive- /EHsc)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN UNICODE _UNICODE)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# ---------------------------------------------------------------------------
# feather_engine: pure detection core. No OS-specific code, no driver deps.
# Everything else (CLI, AMSI provider, minifilter) links against this.
# ---------------------------------------------------------------------------
add_library(feather_engine STATIC
  engine/sha256.cpp
  engine/pe.cpp
  engine/ioc.cpp
  engine/exclusions.cpp
  engine/engine.cpp
  verdict/signal.cpp
  sources/ioc_source.cpp
  sources/rules_source.cpp
  sources/clamav_source.cpp
)
target_include_directories(feather_engine PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

if(WIN32)
  target_link_libraries(feather_engine PUBLIC ws2_32)
endif()

# ---------------------------------------------------------------------------
# feather: user-mode CLI scanner
# ---------------------------------------------------------------------------
add_executable(feather
  cli/main.cpp
  cli/walk.cpp
  cli/cache.cpp
  cli/quarantine.cpp
)
target_link_libraries(feather PRIVATE feather_engine)

if(MSVC)
  target_compile_options(feather PRIVATE /W4)
endif()
