# IdaWorkSpace 

For IDAPro multiple file analysis, handles interdependencies.

Passing symbols upwards (structures, function signatures)

Can be uesd for IDAPro analysis of interdependent library files.

## Ues 

### Install 

Puts the `AWorkSpace.py` and `Aworkspace` folder in the current directory into the IDAPro plugin directory.

### Use 

Shortcut key ALT-F6.

When starting for the first time, you need to specify whether the current analysis file is a client or a server.

* client 

> Use the ALT-F6 shotcut to quickly load symbols from the specified header file. 

* server 

> Automatically export symbols to the specified header file when saving idb files.

After selecting client or server identity, you need to select the specified header file, through which you can connect client and server to form an upward denpendency. 

### Dome



## TODO 
*  The same file acts as both server and client 

    > you can form a tree structure with more dependencies.


* add `build_struct` to the right click.

    > a tools for quickly adding structure.

    > current he can only `from Aworkspace.struct_build import build_struct` then `build_struct(struct_name, struct_size) `

