# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.8

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
CMAKE_COMMAND = /usr/local/bin/cmake

# The command to remove a file.
RM = /usr/local/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/kristtopher/CLionProjects/Jansen

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/kristtopher/CLionProjects/Jansen/build

# Include any dependencies generated for this target.
include CMakeFiles/kmeans-dataflow.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/kmeans-dataflow.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/kmeans-dataflow.dir/flags.make

CMakeFiles/kmeans-dataflow.dir/source/CLI.cpp.o: CMakeFiles/kmeans-dataflow.dir/flags.make
CMakeFiles/kmeans-dataflow.dir/source/CLI.cpp.o: ../source/CLI.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/kristtopher/CLionProjects/Jansen/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/kmeans-dataflow.dir/source/CLI.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/kmeans-dataflow.dir/source/CLI.cpp.o -c /home/kristtopher/CLionProjects/Jansen/source/CLI.cpp

CMakeFiles/kmeans-dataflow.dir/source/CLI.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/kmeans-dataflow.dir/source/CLI.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/kristtopher/CLionProjects/Jansen/source/CLI.cpp > CMakeFiles/kmeans-dataflow.dir/source/CLI.cpp.i

CMakeFiles/kmeans-dataflow.dir/source/CLI.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/kmeans-dataflow.dir/source/CLI.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/kristtopher/CLionProjects/Jansen/source/CLI.cpp -o CMakeFiles/kmeans-dataflow.dir/source/CLI.cpp.s

CMakeFiles/kmeans-dataflow.dir/source/CLI.cpp.o.requires:

.PHONY : CMakeFiles/kmeans-dataflow.dir/source/CLI.cpp.o.requires

CMakeFiles/kmeans-dataflow.dir/source/CLI.cpp.o.provides: CMakeFiles/kmeans-dataflow.dir/source/CLI.cpp.o.requires
	$(MAKE) -f CMakeFiles/kmeans-dataflow.dir/build.make CMakeFiles/kmeans-dataflow.dir/source/CLI.cpp.o.provides.build
.PHONY : CMakeFiles/kmeans-dataflow.dir/source/CLI.cpp.o.provides

CMakeFiles/kmeans-dataflow.dir/source/CLI.cpp.o.provides.build: CMakeFiles/kmeans-dataflow.dir/source/CLI.cpp.o


CMakeFiles/kmeans-dataflow.dir/source/Node.cpp.o: CMakeFiles/kmeans-dataflow.dir/flags.make
CMakeFiles/kmeans-dataflow.dir/source/Node.cpp.o: ../source/Node.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/kristtopher/CLionProjects/Jansen/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/kmeans-dataflow.dir/source/Node.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/kmeans-dataflow.dir/source/Node.cpp.o -c /home/kristtopher/CLionProjects/Jansen/source/Node.cpp

CMakeFiles/kmeans-dataflow.dir/source/Node.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/kmeans-dataflow.dir/source/Node.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/kristtopher/CLionProjects/Jansen/source/Node.cpp > CMakeFiles/kmeans-dataflow.dir/source/Node.cpp.i

CMakeFiles/kmeans-dataflow.dir/source/Node.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/kmeans-dataflow.dir/source/Node.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/kristtopher/CLionProjects/Jansen/source/Node.cpp -o CMakeFiles/kmeans-dataflow.dir/source/Node.cpp.s

CMakeFiles/kmeans-dataflow.dir/source/Node.cpp.o.requires:

.PHONY : CMakeFiles/kmeans-dataflow.dir/source/Node.cpp.o.requires

CMakeFiles/kmeans-dataflow.dir/source/Node.cpp.o.provides: CMakeFiles/kmeans-dataflow.dir/source/Node.cpp.o.requires
	$(MAKE) -f CMakeFiles/kmeans-dataflow.dir/build.make CMakeFiles/kmeans-dataflow.dir/source/Node.cpp.o.provides.build
.PHONY : CMakeFiles/kmeans-dataflow.dir/source/Node.cpp.o.provides

CMakeFiles/kmeans-dataflow.dir/source/Node.cpp.o.provides.build: CMakeFiles/kmeans-dataflow.dir/source/Node.cpp.o


# Object files for target kmeans-dataflow
kmeans__dataflow_OBJECTS = \
"CMakeFiles/kmeans-dataflow.dir/source/CLI.cpp.o" \
"CMakeFiles/kmeans-dataflow.dir/source/Node.cpp.o"

# External object files for target kmeans-dataflow
kmeans__dataflow_EXTERNAL_OBJECTS =

kmeans-dataflow: CMakeFiles/kmeans-dataflow.dir/source/CLI.cpp.o
kmeans-dataflow: CMakeFiles/kmeans-dataflow.dir/source/Node.cpp.o
kmeans-dataflow: CMakeFiles/kmeans-dataflow.dir/build.make
kmeans-dataflow: CMakeFiles/kmeans-dataflow.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/kristtopher/CLionProjects/Jansen/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX executable kmeans-dataflow"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/kmeans-dataflow.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/kmeans-dataflow.dir/build: kmeans-dataflow

.PHONY : CMakeFiles/kmeans-dataflow.dir/build

CMakeFiles/kmeans-dataflow.dir/requires: CMakeFiles/kmeans-dataflow.dir/source/CLI.cpp.o.requires
CMakeFiles/kmeans-dataflow.dir/requires: CMakeFiles/kmeans-dataflow.dir/source/Node.cpp.o.requires

.PHONY : CMakeFiles/kmeans-dataflow.dir/requires

CMakeFiles/kmeans-dataflow.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/kmeans-dataflow.dir/cmake_clean.cmake
.PHONY : CMakeFiles/kmeans-dataflow.dir/clean

CMakeFiles/kmeans-dataflow.dir/depend:
	cd /home/kristtopher/CLionProjects/Jansen/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/kristtopher/CLionProjects/Jansen /home/kristtopher/CLionProjects/Jansen /home/kristtopher/CLionProjects/Jansen/build /home/kristtopher/CLionProjects/Jansen/build /home/kristtopher/CLionProjects/Jansen/build/CMakeFiles/kmeans-dataflow.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/kmeans-dataflow.dir/depend

