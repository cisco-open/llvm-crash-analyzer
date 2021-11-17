# llvm-crash-analyzer

Let’s analyse the crash of your program!
The llvm-crash-analyzer tool is designed to observe/triage crash root from your program && as an outcome it will point to a blame function && machine instruction && line of source code of the problematic piece of the program.

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
    6.	Report critical function


## Building the project

There are various steps && variants/combination of CMake usage on the LLVM project builds, but we will point to the one we use on our CISCO dev machines. For further info, please consider using the link: https://llvm.org/docs/CMake.html.
Steps:

    $ export CXX=/auto/binos-tools/llvm90/llvm-9.0-p0a/bin/clang++ && export CC=/auto/binos-tools/llvm90/llvm-9.0-p0a/bin/clang
    $ export LD_LIBRARY_PATH=/router/lib/:$LD_LIBRARY_PATH
    $ export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/auto/binos-tools/llvm90/llvm-9.0-p0a/lib

    $ mkdir build && cd build
    $ /auto/binos-tools/llvm40/tools/cmake/bin/cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_ASSERTIONS=On -DLLVM_ENABLE_PROJECTS="clang;llvm-crash-analyzer;lldb;" -DLLVM_ENABLE_LIBCXX=ON ../llvm-crash-anal/llvm-10.0.1/llvm -DLLDB_TEST_COMPILER=/auto/binos-tools/llvm90/llvm-9.0-p0a/bin/clang 

    $ make -j30 && make check-crash-blamer -j30

## Using the tool

1) help:

       $ llvm-crash-analyzer --help
       Crash Analyzer -- crash analyzer utility
       OVERVIEW: crash analyzer

       USAGE: llvm-crash-analyzer [options] <input file>

       OPTIONS:

       Generic Options:

         --help                                - Display available options (--help-hidden for more)
         --help-list                           - Display list of available options (--help-list-hidden for more)
         --version                             - Display the version of this program

       Specific Options:

         --core-file=<corefilename>            - <core-file>
         --modules-path=<modulespath>          - <paths>
         --out-file=<filename>                 - Redirect output to the specified file
         --solib-search-path=<solibsearchpath> - <paths>
         --sysroot=<sysrootpath>               - <path>
  
 2) analysis:
 
        $ llvm-crash-analyzer --core-file=core.a.out.9595 ./a.out
        Crash Analyzer -- crash analyzer utility

        Loading core-file core.a.out.9595
        core-file processed.

        Decompiling...
        Decompiling b(int*)
        Decompiling main
        Decompiled.

        Analyzing...

        Blame Function is b(int*)
        From File /nobackup/djtodoro/test.cpp
3) to see some intermediate steps check options such as
   
       i) $ llvm-crash-analyzer --core-file=core.a.out.30988 a.out --print-decompiled-mir=test.mir
       ii) The --show-disassemble option
       iii) visualize the taint DFG:
          $ llvm-crash-analyzer base-case --core-file=core.base-case.40698 --print-dfg-as-dot=base-case.dot
          $ dot -Tpng base-case.dot -o base-case.png
       iiii) ...

## Commiting to the repository
In order to pass every commit through a code reioew process, it is suggested to create a git pull request for each commit. First create a local branch:

       $ git checkout -tb "branch_name" origin/master

Make your changes and commit them locally:

       $ git commit

Push your changes to GitHub:

       $ git push origin branch_name 

This should create a git pull request on GitHub. Once the changes have been approved, you can merge the changes in.
