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
CMAKE_SOURCE_DIR = /home/kristtopher/CLionProjects/kmeansArmadillo

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/kristtopher/CLionProjects/kmeansArmadillo/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/kmeansArmadillo.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/kmeansArmadillo.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/kmeansArmadillo.dir/flags.make

CMakeFiles/kmeansArmadillo.dir/main.cpp.o: CMakeFiles/kmeansArmadillo.dir/flags.make
CMakeFiles/kmeansArmadillo.dir/main.cpp.o: ../main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/kristtopher/CLionProjects/kmeansArmadillo/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/kmeansArmadillo.dir/main.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/kmeansArmadillo.dir/main.cpp.o -c /home/kristtopher/CLionProjects/kmeansArmadillo/main.cpp

CMakeFiles/kmeansArmadillo.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/kmeansArmadillo.dir/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/kristtopher/CLionProjects/kmeansArmadillo/main.cpp > CMakeFiles/kmeansArmadillo.dir/main.cpp.i

CMakeFiles/kmeansArmadillo.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/kmeansArmadillo.dir/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/kristtopher/CLionProjects/kmeansArmadillo/main.cpp -o CMakeFiles/kmeansArmadillo.dir/main.cpp.s

CMakeFiles/kmeansArmadillo.dir/main.cpp.o.requires:

.PHONY : CMakeFiles/kmeansArmadillo.dir/main.cpp.o.requires

CMakeFiles/kmeansArmadillo.dir/main.cpp.o.provides: CMakeFiles/kmeansArmadillo.dir/main.cpp.o.requires
	$(MAKE) -f CMakeFiles/kmeansArmadillo.dir/build.make CMakeFiles/kmeansArmadillo.dir/main.cpp.o.provides.build
.PHONY : CMakeFiles/kmeansArmadillo.dir/main.cpp.o.provides

CMakeFiles/kmeansArmadillo.dir/main.cpp.o.provides.build: CMakeFiles/kmeansArmadillo.dir/main.cpp.o


# Object files for target kmeansArmadillo
kmeansArmadillo_OBJECTS = \
"CMakeFiles/kmeansArmadillo.dir/main.cpp.o"

# External object files for target kmeansArmadillo
kmeansArmadillo_EXTERNAL_OBJECTS =

kmeansArmadillo: CMakeFiles/kmeansArmadillo.dir/main.cpp.o
kmeansArmadillo: CMakeFiles/kmeansArmadillo.dir/build.make
kmeansArmadillo: CMakeFiles/kmeansArmadillo.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/kristtopher/CLionProjects/kmeansArmadillo/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable kmeansArmadillo"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/kmeansArmadillo.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/kmeansArmadillo.dir/build: kmeansArmadillo

.PHONY : CMakeFiles/kmeansArmadillo.dir/build

CMakeFiles/kmeansArmadillo.dir/requires: CMakeFiles/kmeansArmadillo.dir/main.cpp.o.requires

.PHONY : CMakeFiles/kmeansArmadillo.dir/requires

CMakeFiles/kmeansArmadillo.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/kmeansArmadillo.dir/cmake_clean.cmake
.PHONY : CMakeFiles/kmeansArmadillo.dir/clean

CMakeFiles/kmeansArmadillo.dir/depend:
	cd /home/kristtopher/CLionProjects/kmeansArmadillo/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/kristtopher/CLionProjects/kmeansArmadillo /home/kristtopher/CLionProjects/kmeansArmadillo /home/kristtopher/CLionProjects/kmeansArmadillo/cmake-build-debug /home/kristtopher/CLionProjects/kmeansArmadillo/cmake-build-debug /home/kristtopher/CLionProjects/kmeansArmadillo/cmake-build-debug/CMakeFiles/kmeansArmadillo.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/kmeansArmadillo.dir/depend

