# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.7

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
CMAKE_COMMAND = /usr/share/clion-2017.1/bin/cmake/bin/cmake

# The command to remove a file.
RM = /usr/share/clion-2017.1/bin/cmake/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/kristtopher/CLionProjects/WBAN

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/kristtopher/CLionProjects/WBAN/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/WBAN.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/WBAN.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/WBAN.dir/flags.make

CMakeFiles/WBAN.dir/main.cpp.o: CMakeFiles/WBAN.dir/flags.make
CMakeFiles/WBAN.dir/main.cpp.o: ../main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/kristtopher/CLionProjects/WBAN/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/WBAN.dir/main.cpp.o"
	/usr/bin/c++   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/WBAN.dir/main.cpp.o -c /home/kristtopher/CLionProjects/WBAN/main.cpp

CMakeFiles/WBAN.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/WBAN.dir/main.cpp.i"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/kristtopher/CLionProjects/WBAN/main.cpp > CMakeFiles/WBAN.dir/main.cpp.i

CMakeFiles/WBAN.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/WBAN.dir/main.cpp.s"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/kristtopher/CLionProjects/WBAN/main.cpp -o CMakeFiles/WBAN.dir/main.cpp.s

CMakeFiles/WBAN.dir/main.cpp.o.requires:

.PHONY : CMakeFiles/WBAN.dir/main.cpp.o.requires

CMakeFiles/WBAN.dir/main.cpp.o.provides: CMakeFiles/WBAN.dir/main.cpp.o.requires
	$(MAKE) -f CMakeFiles/WBAN.dir/build.make CMakeFiles/WBAN.dir/main.cpp.o.provides.build
.PHONY : CMakeFiles/WBAN.dir/main.cpp.o.provides

CMakeFiles/WBAN.dir/main.cpp.o.provides.build: CMakeFiles/WBAN.dir/main.cpp.o


# Object files for target WBAN
WBAN_OBJECTS = \
"CMakeFiles/WBAN.dir/main.cpp.o"

# External object files for target WBAN
WBAN_EXTERNAL_OBJECTS =

WBAN: CMakeFiles/WBAN.dir/main.cpp.o
WBAN: CMakeFiles/WBAN.dir/build.make
WBAN: CMakeFiles/WBAN.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/kristtopher/CLionProjects/WBAN/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable WBAN"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/WBAN.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/WBAN.dir/build: WBAN

.PHONY : CMakeFiles/WBAN.dir/build

CMakeFiles/WBAN.dir/requires: CMakeFiles/WBAN.dir/main.cpp.o.requires

.PHONY : CMakeFiles/WBAN.dir/requires

CMakeFiles/WBAN.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/WBAN.dir/cmake_clean.cmake
.PHONY : CMakeFiles/WBAN.dir/clean

CMakeFiles/WBAN.dir/depend:
	cd /home/kristtopher/CLionProjects/WBAN/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/kristtopher/CLionProjects/WBAN /home/kristtopher/CLionProjects/WBAN /home/kristtopher/CLionProjects/WBAN/cmake-build-debug /home/kristtopher/CLionProjects/WBAN/cmake-build-debug /home/kristtopher/CLionProjects/WBAN/cmake-build-debug/CMakeFiles/WBAN.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/WBAN.dir/depend

