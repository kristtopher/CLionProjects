# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.9

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /opt/Clion/clion-2017.3.3/bin/cmake/bin/cmake

# The command to remove a file.
RM = /opt/Clion/clion-2017.3.3/bin/cmake/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/kristtopher/CLionProjects/tomcrypt_XTEA

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/kristtopher/CLionProjects/tomcrypt_XTEA/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/tomcrypt_XTEA.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/tomcrypt_XTEA.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/tomcrypt_XTEA.dir/flags.make

CMakeFiles/tomcrypt_XTEA.dir/main.cpp.o: CMakeFiles/tomcrypt_XTEA.dir/flags.make
CMakeFiles/tomcrypt_XTEA.dir/main.cpp.o: ../main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/kristtopher/CLionProjects/tomcrypt_XTEA/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/tomcrypt_XTEA.dir/main.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/tomcrypt_XTEA.dir/main.cpp.o -c /home/kristtopher/CLionProjects/tomcrypt_XTEA/main.cpp

CMakeFiles/tomcrypt_XTEA.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/tomcrypt_XTEA.dir/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/kristtopher/CLionProjects/tomcrypt_XTEA/main.cpp > CMakeFiles/tomcrypt_XTEA.dir/main.cpp.i

CMakeFiles/tomcrypt_XTEA.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/tomcrypt_XTEA.dir/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/kristtopher/CLionProjects/tomcrypt_XTEA/main.cpp -o CMakeFiles/tomcrypt_XTEA.dir/main.cpp.s

CMakeFiles/tomcrypt_XTEA.dir/main.cpp.o.requires:

.PHONY : CMakeFiles/tomcrypt_XTEA.dir/main.cpp.o.requires

CMakeFiles/tomcrypt_XTEA.dir/main.cpp.o.provides: CMakeFiles/tomcrypt_XTEA.dir/main.cpp.o.requires
	$(MAKE) -f CMakeFiles/tomcrypt_XTEA.dir/build.make CMakeFiles/tomcrypt_XTEA.dir/main.cpp.o.provides.build
.PHONY : CMakeFiles/tomcrypt_XTEA.dir/main.cpp.o.provides

CMakeFiles/tomcrypt_XTEA.dir/main.cpp.o.provides.build: CMakeFiles/tomcrypt_XTEA.dir/main.cpp.o


# Object files for target tomcrypt_XTEA
tomcrypt_XTEA_OBJECTS = \
"CMakeFiles/tomcrypt_XTEA.dir/main.cpp.o"

# External object files for target tomcrypt_XTEA
tomcrypt_XTEA_EXTERNAL_OBJECTS =

tomcrypt_XTEA: CMakeFiles/tomcrypt_XTEA.dir/main.cpp.o
tomcrypt_XTEA: CMakeFiles/tomcrypt_XTEA.dir/build.make
tomcrypt_XTEA: CMakeFiles/tomcrypt_XTEA.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/kristtopher/CLionProjects/tomcrypt_XTEA/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable tomcrypt_XTEA"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/tomcrypt_XTEA.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/tomcrypt_XTEA.dir/build: tomcrypt_XTEA

.PHONY : CMakeFiles/tomcrypt_XTEA.dir/build

CMakeFiles/tomcrypt_XTEA.dir/requires: CMakeFiles/tomcrypt_XTEA.dir/main.cpp.o.requires

.PHONY : CMakeFiles/tomcrypt_XTEA.dir/requires

CMakeFiles/tomcrypt_XTEA.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/tomcrypt_XTEA.dir/cmake_clean.cmake
.PHONY : CMakeFiles/tomcrypt_XTEA.dir/clean

CMakeFiles/tomcrypt_XTEA.dir/depend:
	cd /home/kristtopher/CLionProjects/tomcrypt_XTEA/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/kristtopher/CLionProjects/tomcrypt_XTEA /home/kristtopher/CLionProjects/tomcrypt_XTEA /home/kristtopher/CLionProjects/tomcrypt_XTEA/cmake-build-debug /home/kristtopher/CLionProjects/tomcrypt_XTEA/cmake-build-debug /home/kristtopher/CLionProjects/tomcrypt_XTEA/cmake-build-debug/CMakeFiles/tomcrypt_XTEA.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/tomcrypt_XTEA.dir/depend
