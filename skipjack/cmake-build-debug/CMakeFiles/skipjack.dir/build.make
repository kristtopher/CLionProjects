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
CMAKE_SOURCE_DIR = /home/kristtopher/CLionProjects/skipjack

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/kristtopher/CLionProjects/skipjack/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/skipjack.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/skipjack.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/skipjack.dir/flags.make

CMakeFiles/skipjack.dir/main.cpp.o: CMakeFiles/skipjack.dir/flags.make
CMakeFiles/skipjack.dir/main.cpp.o: ../main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/kristtopher/CLionProjects/skipjack/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/skipjack.dir/main.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/skipjack.dir/main.cpp.o -c /home/kristtopher/CLionProjects/skipjack/main.cpp

CMakeFiles/skipjack.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/skipjack.dir/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/kristtopher/CLionProjects/skipjack/main.cpp > CMakeFiles/skipjack.dir/main.cpp.i

CMakeFiles/skipjack.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/skipjack.dir/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/kristtopher/CLionProjects/skipjack/main.cpp -o CMakeFiles/skipjack.dir/main.cpp.s

CMakeFiles/skipjack.dir/main.cpp.o.requires:

.PHONY : CMakeFiles/skipjack.dir/main.cpp.o.requires

CMakeFiles/skipjack.dir/main.cpp.o.provides: CMakeFiles/skipjack.dir/main.cpp.o.requires
	$(MAKE) -f CMakeFiles/skipjack.dir/build.make CMakeFiles/skipjack.dir/main.cpp.o.provides.build
.PHONY : CMakeFiles/skipjack.dir/main.cpp.o.provides

CMakeFiles/skipjack.dir/main.cpp.o.provides.build: CMakeFiles/skipjack.dir/main.cpp.o


# Object files for target skipjack
skipjack_OBJECTS = \
"CMakeFiles/skipjack.dir/main.cpp.o"

# External object files for target skipjack
skipjack_EXTERNAL_OBJECTS =

skipjack: CMakeFiles/skipjack.dir/main.cpp.o
skipjack: CMakeFiles/skipjack.dir/build.make
skipjack: CMakeFiles/skipjack.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/kristtopher/CLionProjects/skipjack/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable skipjack"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/skipjack.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/skipjack.dir/build: skipjack

.PHONY : CMakeFiles/skipjack.dir/build

CMakeFiles/skipjack.dir/requires: CMakeFiles/skipjack.dir/main.cpp.o.requires

.PHONY : CMakeFiles/skipjack.dir/requires

CMakeFiles/skipjack.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/skipjack.dir/cmake_clean.cmake
.PHONY : CMakeFiles/skipjack.dir/clean

CMakeFiles/skipjack.dir/depend:
	cd /home/kristtopher/CLionProjects/skipjack/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/kristtopher/CLionProjects/skipjack /home/kristtopher/CLionProjects/skipjack /home/kristtopher/CLionProjects/skipjack/cmake-build-debug /home/kristtopher/CLionProjects/skipjack/cmake-build-debug /home/kristtopher/CLionProjects/skipjack/cmake-build-debug/CMakeFiles/skipjack.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/skipjack.dir/depend

