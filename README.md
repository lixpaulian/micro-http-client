# micro-http-client
A compact http/s client written in C++ suitable for embedded systems. It was specifically developed for µOS++ but can be ported to other POSIX compliant RTOSes.

## Version
* 0.9.1 (21 Jan 2023)

## License
* MIT

## Package
The software is provided as an xPack and can be installed in an Eclipse based project (however, the `include` and `source` paths must be manually added to the project in Eclipse). For more details on xPacks see https://github.com/xpacks. The installation script requires the helper scripts that can be found at https://github.com/xpacks/scripts. Note that currently the xpacks project is undergoing structural changes and therefore the `scripts` directory will be deprecated.

## Dependencies
This software depends on the following package, available as xPack:
* µOS++ (https://github.com/micro-os-plus/micro-os-plus-iii)

In addition, the software requires a TCP/IP stack and, if https is also envisaged, an SSL library. The project has been developed using the combination of LwIP and mbdedTLS. These packages have been forked from their respective repositories as follows:

* LwIP version 2.1.4 (https://git.savannah.nongnu.org/git/lwip.git)
* mbedTLS version 2.28.2 LTS (https://github.com/ARMmbed/mbedtls.git)

## Project Roots
This project is largely based on `minihttp` written by fgenesis (https://github.com/fgenesis/minihttp) and licensed under the WTFPL. However, the scope of this project has been narrowed to focus primarily on embedded systems based on small 32-bit ARM Cortex M4/M7 controllers with reduced amounts of RAM. Compared to the original project, `micro-http-client` differs in several aspects:
* Gave up on the use of STL's string() and map() calls, due to their extensive use of dynamic allocation.
* Gave up the compatibility to Linux and Windows to streamline the code (however, backporting to POSIX compliant platforms should be relatively simple).
* Removed socket sets and gave up on multiple connections on a single thread. Only one socket/connection per http/s client thread is used at a time (however, multiple http/s contexts are still possible in a multithreaded environment as e.g. with µOS++).
* Refactored the code for better readability, see http://micro-os-plus.github.io/develop/coding-style (note however, that I don't claim to implement all the recommendations).
* Changed the WTFPL license to MIT License.
