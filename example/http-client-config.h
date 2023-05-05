/*
 * http-client-config.h
 *
 * Copyright (c) 2023 Lix N. Paulian (lix@paulian.net)
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom
 * the Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Created on: 23 Feb 2023 (LNP)
 *
 */

#ifndef EXAMPLE_HTTP_CLIENT_CONFIG_H_
#define EXAMPLE_HTTP_CLIENT_CONFIG_H_

// accept TLS v1.1 and up
#define MBEDTLS_SSL_MINOR_VERSION MBEDTLS_SSL_MINOR_VERSION_2
#define MBEDTLS_SOCKET_RW_TIMEOUT 60
#define HTTPC_DEBUG 1

#endif /* EXAMPLE_HTTP_CLIENT_CONFIG_H_ */
