# micro-http-client
A compact http/s client written in C++ suitable for embedded systems. It was specifically developed for µOS++ but can be ported to other POSIX compliant RTOSes.

## Version
* 0.9.3 (24 Jan 2023)

## License
* MIT

## Package
The software is provided as an xPack and can be added to an Eclipse based project (however, the `include` and `source` paths must be manually added to the project in Eclipse). For more details on xPacks see https://github.com/xpacks. The installation script requires the helper scripts that can be found at https://github.com/xpacks/scripts. Note that currently the xpacks project is undergoing structural changes and therefore the `scripts` directory will be deprecated.
Of course, the files can be also manually added to any project.

## Dependencies
This software depends on the following package, available as xPack:
* µOS++ (https://github.com/micro-os-plus/micro-os-plus-iii)

In addition, the software requires a TCP/IP stack and, if https is also envisaged, an SSL library. The project has been developed using the combination of LwIP and mbdedTLS. These packages have been forked from their respective repositories as follows:

* LwIP version 2.1.4 (https://git.savannah.nongnu.org/git/lwip.git)
* mbedTLS version 2.28.2 LTS (https://github.com/ARMmbed/mbedtls.git)

## Project Roots
This project is largely based on `minihttp` written by fgenesis (https://github.com/fgenesis/minihttp) and licensed under the WTFPL. However, the scope of this project has been narrowed to focus primarily on embedded systems based on small 32-bit ARM Cortex M4/M7 controllers with reduced amounts of RAM. Compared to the original project, `micro-http-client` differs in several aspects:
* It doesn't use STL's string() and map() calls, due to their extensive use of dynamic memory allocation.
* Gave up the compatibility to Linux and Windows to streamline the code (however, back-porting to POSIX compliant platforms should be relatively simple - but then better use the original code, `minihttp`).
* Removed socket sets and gave up on multiple connections on a single thread. Only one socket/connection per http/s client thread is used at a time; however, multiple http/s contexts are still possible in a multithreaded environment as e.g. with µOS++.
* Refactored the code for better readability, see http://micro-os-plus.github.io/develop/coding-style (note however, that I don't claim to implement all the recommendations).
* Changed the WTFPL license to MIT License.

## How to Use
In the `example` directory you will find reference code showing how to integrate the http client in your code. There are however several prerequisites:
* The hardware initialisation of your board or device must be properly done, including the ethernet driver or ppp over serial code.
* LwIP and mbedTLS must be already linked to your code and operational (tested).
* You need about 128 KBytes of RAM; depending on what the rest of your code does/need, it can be less or can be more). That is because `mbdedTLS` needs quite some RAM (most of it dynamically allocated).
* Optionally a file system.
The example has been successfully tested on a STM32F746G-DISCO Board using only the controller's 340 KBytes on board RAM (https://www.st.com/en/evaluation-tools/32f746gdiscovery.html). The project includes many other modules (RTOS, file system, HTTP/S server, TFTP, NTP, and more) and there are still about 180 KBytes RAM available.
The `http-client.cpp` file contains an example implementation of the http client. The new class derived from the http_socket includes the initialisation and call-back functions as we saw fit for this example, but feel free to design it in such a way as to suit your needs.
In `example.cpp` it is shown how the functions of the new class are called to test the http client:
* a simple HTTPS GET
* a HTTP GET redirected to a HTTPS GET
* a HTTP POST
* a HTTP GET to download a file to the file system
Note: If you do not have a file system on your target, set the symbol `FILE_SYSTEM` to false (in `http-client.h`), then no file download test will be performed.

## CA Certificates
You may notice that the file `http-client.cpp` includes several certificates. You may need to add or remove certificates, depending on where you want to connect your http client to. For more information on this issue, please consult the mbedTLS web site (in particular https://os.mbed.com/docs/mbed-os/v5.15/tutorials/tls-tutorial.html).
