# Description

A GNU/Linux ASLR bypass PoC created by [Prof. Herbert Bos] (http://www.cs.vu.nl/~herbertb/) and last updated in 2008. The original tutorial can be found [here] (http://www.cs.vu.nl/~herbertb/misc/bufferoverflow/).

While following the tutorial, I noticed my system (vanilla Ubuntu 14.04 x86) uses a different stack variable alignment. 

As such, my contribution is in adjusting the files such that they can be used on a modern GNU/Linux system.

Should you want to get the files and follow the tutorial, use git to clone the repository and start reading the provided [readme] (src/00README.txt) file.