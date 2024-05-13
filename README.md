# file recovery tool
## Overview
This is a tool that recovers a deleted file specified by the user. It is assumed that the deleted file is in the root directory.
## Compile & Run Guide
Prerequisites: 
- Install GCC for C compilation.
- Install Make for build automation.
- Clone repo

To compile: open Mac/Linux terminal or MinGW for windows. Cd to directory of cloned repo. Run following command on the cli: <br>

``` make ```
<br><br>
Executable file should appear now. Now run:

``` ./nyufile ```

To remove object files and the executable, freeing up space, you can use:

``` make clean ```
