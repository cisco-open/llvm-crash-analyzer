# crash-blamer

Let’s analyse the crash of your program!
The crash-blamer tool is designed to observe/triage crash root from your program && as an outcome it will point to a blame function && machine instruction && line of source code of the problematic piece of the program.

The project is based on LLVM ecosystem and it uses the libraries to maintain/deal with low level stuff. It also uses LLDB library to manipulate with debug info and core files provided.


## How it works

There are multiple phases as following:

    1.	Read the input file
    2.	Extract the corresponding core file (for the crash)
      - read function frames from the crash
      - read register && memory state at the time of the crash
    3.	Disassemble the binary
    4.	Decompile the disassembly to LLVM MIR
    5.	Perform Taint Analysis on the LLVM MIR
    6.	Output the blame tuple info


## Building the project

There are various steps && variants/combination of CMake usage on the LLVM project builds, but we will point to the one we use on our CISCO dev machines. For further info, please consider using the link: https://llvm.org/docs/CMake.html.
Steps:

$ export CXX=/auto/binos-tools/llvm90/llvm-9.0-p0a/bin/clang++ && export CC=/auto/binos-tools/llvm90/llvm-9.0-p0a/bin/clang   
$ export LD_LIBRARY_PATH=/router/lib/:$LD_LIBRARY_PATH
$ export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/auto/binos-tools/llvm90/llvm-9.0-p0a/lib

$ mkdir build && cd build
$ /auto/binos-tools/llvm40/tools/cmake/bin/cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_ASSERTIONS=On -DLLVM_ENABLE_PROJECTS="clang;crash-blamer;lldb;" -DLLVM_ENABLE_LIBCXX=ON ../llvm-10.0.1/llvm -DLLDB_TEST_COMPILER=/auto/binos-tools/llvm90/llvm-9.0-p0a/bin/clang 

$ make -j30 && make check-crash-blamer -j30

## Using the tool

1) help:

       $ crash-blamer --help
       Crash Blamer -- crash analyzer utility
       OVERVIEW: crash blamer

       USAGE: crash-blamer [options] <input file>

       OPTIONS:

       Generic Options:

       --help                     - Display available options (--help-hidden for more)
       --help-list                - Display list of available options (--help-list-hidden for more)
       --version                  - Display the version of this program

       Specific Options:

        --core-file=<corefilename> - <core-file>
        --out-file=<filename>      - Redirect output to the specified file
  
 2) analysis:
 
        $ crash-blamer --core-file=core  ./test
        Crash Blamer -- crash analyzer utility

        Loading core-file core
        core-file processed.

        Decompiling...
        Decompiled.

3) to see some intermediate steps check options such as
   
       i) export-to-mir
       ii) show-disassemble
       iii) ...

## Commiting to the repository
In order to pass every commit through a code reioew process, it is suggested to create a git pull request for each commit. First create a local branch:

       $ git checkout -tb "branch_name" origin/master

Make your changes and commit them locally:

       $ git commit

Push your changes to GitHub:

       $ git push origin branch_name 

This should create a git pull request on GitHub. Once the changes have been approved, you can merge the changes in.
