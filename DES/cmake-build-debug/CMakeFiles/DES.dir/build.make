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
CMAKE_SOURCE_DIR = /home/kristtopher/CLionProjects/DES

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/kristtopher/CLionProjects/DES/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/DES.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/DES.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/DES.dir/flags.make

CMakeFiles/DES.dir/main.cpp.o: CMakeFiles/DES.dir/flags.make
CMakeFiles/DES.dir/main.cpp.o: ../main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/kristtopher/CLionProjects/DES/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/DES.dir/main.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/DES.dir/main.cpp.o -c /home/kristtopher/CLionProjects/DES/main.cpp

CMakeFiles/DES.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/DES.dir/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/kristtopher/CLionProjects/DES/main.cpp > CMakeFiles/DES.dir/main.cpp.i

CMakeFiles/DES.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/DES.dir/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/kristtopher/CLionProjects/DES/main.cpp -o CMakeFiles/DES.dir/main.cpp.s

CMakeFiles/DES.dir/main.cpp.o.requires:

.PHONY : CMakeFiles/DES.dir/main.cpp.o.requires

CMakeFiles/DES.dir/main.cpp.o.provides: CMakeFiles/DES.dir/main.cpp.o.requires
	$(MAKE) -f CMakeFiles/DES.dir/build.make CMakeFiles/DES.dir/main.cpp.o.provides.build
.PHONY : CMakeFiles/DES.dir/main.cpp.o.provides

CMakeFiles/DES.dir/main.cpp.o.provides.build: CMakeFiles/DES.dir/main.cpp.o


# Object files for target DES
DES_OBJECTS = \
"CMakeFiles/DES.dir/main.cpp.o"

# External object files for target DES
DES_EXTERNAL_OBJECTS =

DES: CMakeFiles/DES.dir/main.cpp.o
DES: CMakeFiles/DES.dir/build.make
DES: CMakeFiles/DES.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/kristtopher/CLionProjects/DES/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable DES"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/DES.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/DES.dir/build: DES

.PHONY : CMakeFiles/DES.dir/build

CMakeFiles/DES.dir/requires: CMakeFiles/DES.dir/main.cpp.o.requires

.PHONY : CMakeFiles/DES.dir/requires

CMakeFiles/DES.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/DES.dir/cmake_clean.cmake
.PHONY : CMakeFiles/DES.dir/clean

CMakeFiles/DES.dir/depend:
	cd /home/kristtopher/CLionProjects/DES/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/kristtopher/CLionProjects/DES /home/kristtopher/CLionProjects/DES /home/kristtopher/CLionProjects/DES/cmake-build-debug /home/kristtopher/CLionProjects/DES/cmake-build-debug /home/kristtopher/CLionProjects/DES/cmake-build-debug/CMakeFiles/DES.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/DES.dir/depend

