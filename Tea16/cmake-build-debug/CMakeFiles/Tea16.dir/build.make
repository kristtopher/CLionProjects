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
CMAKE_SOURCE_DIR = /home/kristtopher/CLionProjects/Tea16

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/kristtopher/CLionProjects/Tea16/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/Tea16.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/Tea16.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/Tea16.dir/flags.make

CMakeFiles/Tea16.dir/main.cpp.o: CMakeFiles/Tea16.dir/flags.make
CMakeFiles/Tea16.dir/main.cpp.o: ../main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/kristtopher/CLionProjects/Tea16/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/Tea16.dir/main.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/Tea16.dir/main.cpp.o -c /home/kristtopher/CLionProjects/Tea16/main.cpp

CMakeFiles/Tea16.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/Tea16.dir/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/kristtopher/CLionProjects/Tea16/main.cpp > CMakeFiles/Tea16.dir/main.cpp.i

CMakeFiles/Tea16.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/Tea16.dir/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/kristtopher/CLionProjects/Tea16/main.cpp -o CMakeFiles/Tea16.dir/main.cpp.s

CMakeFiles/Tea16.dir/main.cpp.o.requires:

.PHONY : CMakeFiles/Tea16.dir/main.cpp.o.requires

CMakeFiles/Tea16.dir/main.cpp.o.provides: CMakeFiles/Tea16.dir/main.cpp.o.requires
	$(MAKE) -f CMakeFiles/Tea16.dir/build.make CMakeFiles/Tea16.dir/main.cpp.o.provides.build
.PHONY : CMakeFiles/Tea16.dir/main.cpp.o.provides

CMakeFiles/Tea16.dir/main.cpp.o.provides.build: CMakeFiles/Tea16.dir/main.cpp.o


# Object files for target Tea16
Tea16_OBJECTS = \
"CMakeFiles/Tea16.dir/main.cpp.o"

# External object files for target Tea16
Tea16_EXTERNAL_OBJECTS =

Tea16: CMakeFiles/Tea16.dir/main.cpp.o
Tea16: CMakeFiles/Tea16.dir/build.make
Tea16: CMakeFiles/Tea16.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/kristtopher/CLionProjects/Tea16/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable Tea16"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/Tea16.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/Tea16.dir/build: Tea16

.PHONY : CMakeFiles/Tea16.dir/build

CMakeFiles/Tea16.dir/requires: CMakeFiles/Tea16.dir/main.cpp.o.requires

.PHONY : CMakeFiles/Tea16.dir/requires

CMakeFiles/Tea16.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/Tea16.dir/cmake_clean.cmake
.PHONY : CMakeFiles/Tea16.dir/clean

CMakeFiles/Tea16.dir/depend:
	cd /home/kristtopher/CLionProjects/Tea16/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/kristtopher/CLionProjects/Tea16 /home/kristtopher/CLionProjects/Tea16 /home/kristtopher/CLionProjects/Tea16/cmake-build-debug /home/kristtopher/CLionProjects/Tea16/cmake-build-debug /home/kristtopher/CLionProjects/Tea16/cmake-build-debug/CMakeFiles/Tea16.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/Tea16.dir/depend
