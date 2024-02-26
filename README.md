![GitHub package.json version](https://img.shields.io/github/package-json/v/lixpaulian/micro-http-client)
![GitHub Tag](https://img.shields.io/github/v/tag/lixpaulian/micro-http-client)
![GitHub License](https://img.shields.io/github/license/lixpaulian/micro-http-client)

# micro-http-client
A compact http/s client written in C++ suitable for embedded systems. It was specifically developed for µOS++ but can be ported to other POSIX compliant RTOSes.

## Package
The class is provided as an **xPack** (for more details on xPacks see https://xpack.github.io). It can be installed in a project using either `xpm` or the attached script. Of course, it can be installed without using the xPacks tools, either by linking the class as a Git submodule or by copying it in your project, but then updating it later might be more difficult.

Note that the xPacks project evolved with the time. Initially it was based on shell scripts, but the current version is based on a set of utilities, `xpm` and a JSON description file. You will still find the `xpacks-helper.sh` script in the `scripts` subdirectory, but it is not recommened as it is deprecated and will not be supported in the future. Instead use the procedure described below.

To install the package using `xpm` you must make sure that you have already `nodejs` and `xpm` installed on your computer (see also [xPack install](https://xpack.github.io/install/)). Then, in your project directory issue the commands:

```sh
cd my-project
xpm init # Add a package.json if not already present
xpm install github:lixpaulian/micro-http-client#v1.0.0 --save-dev --copy
```

Note: Without `--copy`, the default is to create a link to a read-only instance of the package in the `xpm` central store.

## Dependencies
This software depends on the following package, available as xPack:
* µOS++ (https://github.com/micro-os-plus/micro-os-plus-iii)

In addition, the software requires a TCP/IP stack and, if https is also envisaged, an SSL library. The project has been developed using the combination of LwIP and mbedTLS. These packages have been forked from their respective repositories as follows:

* LwIP version 2.1.4 (https://git.savannah.nongnu.org/git/lwip.git)
* mbedTLS version 2.28.2 LTS (https://github.com/ARMmbed/mbedtls.git)

## Project Roots
This project is largely based on `minihttp` written by fgenesis (https://github.com/fgenesis/minihttp) and licensed under the WTFPL. However, the scope of this project has been narrowed to focus primarily on embedded systems based on small 32-bit ARM Cortex M4/M7 controllers with reduced amounts of RAM. Compared to the original project, `micro-http-client` differs in several aspects:
* It doesn't use STL's `string()` and `map()` calls, due to their extensive use of dynamic memory allocation.
* Gave up the compatibility to Linux and Windows to streamline the code (however, back-porting to POSIX compliant platforms should be relatively simple - but then better use the original code, `minihttp`).
* Removed socket sets and gave up on multiple connections on a single thread. Only one socket/connection per http/s client thread is used at a time; however, multiple http/s contexts are still possible in a multithreaded environment as e.g. under µOS++.
* Refactored the code for better readability, see http://micro-os-plus.github.io/develop/coding-style (note however, that I don't claim to implement all the recommendations).
* The new resulting project is licensed under the MIT License.

## How to Use
In the `example` directory you will find reference code showing how to integrate the http client in your project. There are however several prerequisites:
* The hardware initialisation of your board or device must be properly done, including the ethernet driver or ppp over serial code.
* `LwIP` and `mbedTLS` must be already linked to your code and operational (tested).
* You need about 128 KBytes of RAM; depending on what the rest of your code does/needs, it can be less or can be more. That is because `mbedTLS` needs quite some RAM (and much of it dynamically allocated).
* A console where you can output the results (can be also a trace output). You must define the symbol `PRINTF_` accordingly (in `example.cpp`).
* Optionally a file system.
* There are certain parameters that can be configured through their respective definitions in the http-client-config.h file. If the defaults are okay for you, you can leave the file empty; however, the file is needed otherwise you get a compile error.

The example has been successfully tested on a STM32F746G-DISCO Board (https://www.st.com/en/evaluation-tools/32f746gdiscovery.html) using only the controller's 340 KBytes on-chip RAM. The project includes other modules too (RTOS, file system, HTTP/S server, TFTP, NTP, and more) and there are still about 180 KBytes RAM available.

The `http-client.cpp` file contains an example implementation of the http client. The new class derived from `http_socket` includes the initialisation and call-back functions as we saw fit for this example, but feel free to design it in such a way as to suit your needs.

In `example.cpp` it is shown how the functions of the new class are called to test the http client:
* a simple HTTPS GET
* a HTTP GET redirected to a HTTPS GET
* a HTTPS POST
* a HTTPS GET to download a file to the file system

If the test is run immediately after the hardware is powered on, you should allow at least 10 seconds from power-up until the test is run to let the IP stack to configure, particularly if the IP address is obtained via DHCP.

Note: If you do not have a file system on your target, set the symbol `FILE_SYSTEM` to false (in `http-client.h`), then no file download test will be performed.

## Blocking on Sockets at Read or Write
Depending on the particular hardware you will run the project on, if the IP connection breaks (e.g. Ethernet cable pulled off or low radio signal on wireless connections) the software may block waiting on a socket read or write. There are various schemes to handle such cases as e.g. setting non-blocking flag on the sockets, using the `select()` API or setting a timeout on the sockets. The later method was implemented in the http client, however you must add a function to the `net_sockets.c` file (this implements the `mbedtls` interface to `LwIP`), as shown below:

```c
/*
 * Proprietary call to set a socket timeout (in seconds) at read and write
 */
int
mbedtls_net_set_timeout (mbedtls_net_context* ctx, int seconds)
{
  int ret;

  struct timeval timeout =
    { .tv_sec = seconds, .tv_usec = 0 };

  if ((ret = setsockopt(ctx->fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                        sizeof(timeout))) == 0)
    {
      ret = setsockopt(ctx->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                       sizeof(timeout));
    }

  return ret;
}
```

The timeout can be set in the `http-client-config.h` file using the `MBEDTLS_SOCKET_RW_TIMEOUT` definition and is given in seconds. If set to 0, the socket blocks until data is received or sent.

## CA Certificates
You may notice that the file `http-client.cpp` includes several certificates. You may need to add or remove certificates, depending on where you want to connect your http client to. For more information on this issue, please consult the mbedTLS web site (in particular https://os.mbed.com/docs/mbed-os/v5.15/tutorials/tls-tutorial.html).
