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
CMAKE_SOURCE_DIR = /home/kristtopher/CLionProjects/receiver

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/kristtopher/CLionProjects/receiver/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/receiver.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/receiver.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/receiver.dir/flags.make

CMakeFiles/receiver.dir/main.cpp.o: CMakeFiles/receiver.dir/flags.make
CMakeFiles/receiver.dir/main.cpp.o: ../main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/kristtopher/CLionProjects/receiver/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/receiver.dir/main.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/receiver.dir/main.cpp.o -c /home/kristtopher/CLionProjects/receiver/main.cpp

CMakeFiles/receiver.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/receiver.dir/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/kristtopher/CLionProjects/receiver/main.cpp > CMakeFiles/receiver.dir/main.cpp.i

CMakeFiles/receiver.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/receiver.dir/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/kristtopher/CLionProjects/receiver/main.cpp -o CMakeFiles/receiver.dir/main.cpp.s

CMakeFiles/receiver.dir/main.cpp.o.requires:

.PHONY : CMakeFiles/receiver.dir/main.cpp.o.requires

CMakeFiles/receiver.dir/main.cpp.o.provides: CMakeFiles/receiver.dir/main.cpp.o.requires
	$(MAKE) -f CMakeFiles/receiver.dir/build.make CMakeFiles/receiver.dir/main.cpp.o.provides.build
.PHONY : CMakeFiles/receiver.dir/main.cpp.o.provides

CMakeFiles/receiver.dir/main.cpp.o.provides.build: CMakeFiles/receiver.dir/main.cpp.o


# Object files for target receiver
receiver_OBJECTS = \
"CMakeFiles/receiver.dir/main.cpp.o"

# External object files for target receiver
receiver_EXTERNAL_OBJECTS =

receiver: CMakeFiles/receiver.dir/main.cpp.o
receiver: CMakeFiles/receiver.dir/build.make
receiver: /usr/local/lib/libtomcrypt.a
receiver: CMakeFiles/receiver.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/kristtopher/CLionProjects/receiver/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable receiver"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/receiver.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/receiver.dir/build: receiver

.PHONY : CMakeFiles/receiver.dir/build

CMakeFiles/receiver.dir/requires: CMakeFiles/receiver.dir/main.cpp.o.requires

.PHONY : CMakeFiles/receiver.dir/requires

CMakeFiles/receiver.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/receiver.dir/cmake_clean.cmake
.PHONY : CMakeFiles/receiver.dir/clean

CMakeFiles/receiver.dir/depend:
	cd /home/kristtopher/CLionProjects/receiver/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/kristtopher/CLionProjects/receiver /home/kristtopher/CLionProjects/receiver /home/kristtopher/CLionProjects/receiver/cmake-build-debug /home/kristtopher/CLionProjects/receiver/cmake-build-debug /home/kristtopher/CLionProjects/receiver/cmake-build-debug/CMakeFiles/receiver.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/receiver.dir/depend

