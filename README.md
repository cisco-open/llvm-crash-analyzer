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

    $ cd llvm-project
    $ mkdir build && cd build
    $ cmake -G "Unix Makefiles" -DLLVM_ENABLE_PROJECTS="clang;llvm-crash-analyzer;lldb;" -DLLVM_ENABLE_LIBCXX=ON ../llvm -DLLDB_TEST_COMPILER=clang
    $ make && make check-crash-blamer

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
        From File test.cpp
2a) to see the flow of the critical value

        $ llvm-crash-analyzer --core-file=core.base-case.40698 base-case --print-taint-value-flow-as-dot=test.dot
        $ dot -Tpng test.dot -o test.png

2b) to see the potential location (line:column) of the cause for the crash

        $ llvm-crash-analyzer --core-file=core.base-case.40698 base-case --print-potential-crash-cause-loc
        Crash Analyzer -- crash analyzer utility
        
        Loading core-file core.base-case.40698
        core-file processed.
        
        Decompiling...
        Decompiling f
        Decompiling g
        Decompiling h
        Decompiling main
        Decompiled.

        Analyzing...

        Blame Function is f
        From File test0.c:18:8


3) to see some intermediate steps check options such as
   
       i) $ llvm-crash-analyzer --core-file=core.a.out.30988 a.out --print-decompiled-mir=test.mir
       ii) The --show-disassemble option
       iii) visualize the taint DFG:
          $ llvm-crash-analyzer base-case --core-file=core.base-case.40698 --print-dfg-as-dot=base-case.dot
          $ dot -Tpng base-case.dot -o base-case.png
       iiii) ...
