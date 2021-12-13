file(GLOB_RECURSE xiloader_sources CONFIGURE_DEPENDS *.cpp)

add_executable(xiloader ${xiloader_sources})

find_library(detours_LIB detours "detours")
target_link_libraries(xiloader ${detours_LIB})
