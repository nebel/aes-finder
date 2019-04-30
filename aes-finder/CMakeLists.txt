cmake_minimum_required(VERSION 3.7.2)

project(aes-finder)

set(CMAKE_CONFIGURATION_TYPES "Debug;Profile;Release"
		CACHE STRING "Configuration types" FORCE)

add_executable(aes-finder
		src/aes-finder.cpp
		src/aes-finder.hpp
		src/aes-finder_os.hpp
		src/aes-finder-test.hpp
		)
# Preprocessor definitions
target_compile_definitions(aes-finder PRIVATE
		$<$<CONFIG:Debug>:NOMINMAX;WIN32;_DEBUG;_CONSOLE;_LIB>
		$<$<CONFIG:Profile>:NOMINMAX;WIN32;NDEBUG;_CONSOLE;_LIB>
		$<$<CONFIG:Release>:NOMINMAX;WIN32;NDEBUG;_CONSOLE;_LIB>
		)

# Minimal rebuild
if (MSVC)
	target_compile_options(aes-finder PRIVATE
			"$<$<CONFIG:Debug>:/Gm->"
			"$<$<CONFIG:Profile>:/Gm->"
			"$<$<CONFIG:Release>:/Gm->"
			)
endif ()

# Precompiled header files
if (MSVC)
	target_compile_options(aes-finder PRIVATE
			""
			)
endif ()
