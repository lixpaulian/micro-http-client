/*
 * http-engine.h
 *
 * Copyright (c) 2022-2023 Lix N. Paulian (lix@paulian.net)
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
 * Created on: 9 Dec 2022 (LNP)
 *
 * This software is based on the project "minihttp" by fgenesis
 * (https://github.com/fgenesis/minihttp). For more details see also
 * the README.md file.
 */

#ifndef HTTP_ENGINE_H
#define HTTP_ENGINE_H

#include <stdlib.h>

#include <mbedtls_config.h>
#include <mbedtls/net.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include "http-client-config.h"

// configurable definitions, customization should be done in http-client-config.h

// define the header buffer to fit the longest header to be sent at a request
#if !defined REQUEST_HEADER_BUFFER_LEN
#define REQUEST_HEADER_BUFFER_LEN 512
#endif

// should be large enough to accommodate the largest redirect URL expected
#if !defined REDIRECT_BUFFER_LEN
#define REDIRECT_BUFFER_LEN 128
#endif

// should be large enough to accommodate the largest host name, both requested
// and as the result of a redirect
#if !defined HOSTNAME_BUFFER_LEN
#define HOSTNAME_BUFFER_LEN 64
#endif

// to reduce dynamic memory allocation set it to true
#if !defined STATIC_SSL_CONTEXT
#define STATIC_SSL_CONTEXT false
#endif

// define the accepted security level (see include/mbedtls/ssl.h)
#if !defined MBEDTLS_SSL_MAJOR_VERSION
#define MBEDTLS_SSL_MAJOR_VERSION MBEDTLS_SSL_MAJOR_VERSION_3
#endif

// in combination with MBEDTLS_SSL_MAJOR_VERSION_3, this gives TLS v1.2
#if !defined MBEDTLS_SSL_MINOR_VERSION
#define MBEDTLS_SSL_MINOR_VERSION MBEDTLS_SSL_MINOR_VERSION_3
#endif

// can be NONE, OPTIONAL, REQUIRED, UNSET (see include/mbedtls/ssl.h)
#if !defined MBEDTLS_SSL_VERIFY
#define MBEDTLS_SSL_VERIFY MBEDTLS_SSL_VERIFY_REQUIRED
#endif

// set debug level: 0 - no debug, 1 - light, 2 - fair, 3 - heavy debug messages
#if !defined HTTPC_DEBUG
#define HTTPC_DEBUG 0
#endif

//------------------------------------------------------------------------------

namespace micro_http_client
{

  class ssl_context
  {
  public:

    ssl_context (void);

    ~ssl_context (void);

    int
    init (void);

    void
    reset (void);

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_x509_crt cacert;
    mbedtls_ssl_config conf;
  };

  //----------------------------------------------------------------------------

  class tcp_socket
  {
  public:

    tcp_socket (uint8_t* buff, size_t len);

    virtual
    ~tcp_socket ();

    typedef intptr_t SOCKET;

    bool
    open (const char* addr, unsigned int port, bool useSSL);

    void
    close (void);

    // returns true if something interesting happened (incoming data,
    // closed connection, etc)
    bool
    update (void);

    bool
    is_open (void);

    bool
    set_non_blocking (bool nonblock);

    const char*
    get_host (void)
    {
      return last_host_;
    }

    bool
    send_bytes (const void* buf, unsigned int len);

    // SSL related
    enum ssl_result_t
    {
      SSLR_OK = 0x0,
      SSLR_NO_SSL = 0x1,
      SSLR_FAIL = 0x2,
      SSLR_CERT_EXPIRED = 0x4,
      SSLR_CERT_REVOKED = 0x8,
      SSLR_CERT_CN_MISMATCH = 0x10,
      SSLR_CERT_NOT_TRUSTED = 0x20,
      SSLR_CERT_MISSING = 0x40,
      SSLR_CERT_SKIP_VERIFY = 0x80,
      SSLR_CERT_FUTURE = 0x100,

      _SSLR_FORCE32BIT = 0x7fffffff
    };

    bool
    init_ssl (const char* certs);

    void
    set_certs (const char* certs);

    ssl_result_t
    verify_ssl (char* buf, unsigned buflen);

    int
    get_last_error (void)
    {
      return -mbedtls_error_;
    }

  protected:

    bool
    open_socket (SOCKET* ps, const char* host, unsigned port);

    bool
    open_ssl (void* ps);

    virtual void
    on_close_internal (void);

    virtual void
    on_data (); // data received callback; internal, should only be overloaded
                // to call on_recv ()

    virtual void
    on_recv (uint8_t* buf, unsigned int size) = 0;

    virtual void
    on_close (void)
    {
    } // close callback

    virtual void
    on_open (void)
    {
    } // called when opened

    virtual bool
    on_update (void)
    {
      return true;
    } // called before reading from the socket

    void
    shift_buffer ();

    uint8_t* inbuf_;
    uint8_t* readptr_;  // part of inbuf, optionally skipped header
    uint8_t* writeptr_; // passed to recv(). usually equal to inbuf_, but may
                        // point inside the buffer in case of a partial transfer.

    size_t inbuf_size_; // size of internal buffer
    size_t write_size_; // how many bytes can be written to writeptr_;
    size_t recv_size_;  // incoming data size, max inbuf_size_ - 1
    bool append_;

    long s_;
    bool nonblocking_;  // default true, otherwise the current thread is blocked
                        // while waiting for input
    ssl_context* ctx_;

    const char* last_host_;
    unsigned int last_port_; // port used in last open() call
    int mbedtls_error_;  // last error returned by mbedtls

  private:

    int
    write_bytes (const unsigned char* buf, size_t len);

    int
    read_bytes (unsigned char* buf, size_t maxlen);

    bool ssl_inited_;
    bool use_ssl_;
    const char* certs_;
  };

  //----------------------------------------------------------------------------

  class http_socket : public tcp_socket
  {
  public:

    http_socket (uint8_t* buff, size_t len);

    virtual
    ~http_socket ();

    struct request
    {
      char* protocol;
      char* host;
      char* header;
      char* resource;
      char* extra_header;
      unsigned int port;
      bool useSSL;
      const char* post; // if null, it's a GET, otherwise a POST request
      size_t post_len;
    };

    void
    set_keep_alive (unsigned int secs)
    {
      keep_alive_ = secs;
    }

    void
    set_user_agent (const char* s)
    {
      user_agent_ = s;
    }

    void
    set_accept_encoding (const char* s)
    {
      accept_encoding_ = s;
    }

    void
    set_content_type (const char* s)
    {
      content_type_ = s;
    }

    void
    set_folllow_redirect (bool follow)
    {
      follow_redir_ = follow;
    }

    void
    set_always_handle (bool h)
    {
      always_handle_ = h;
    }

    bool
    transaction (const char* url, char* extra_header, const char* post,
                 size_t post_len);

    bool
    split_uri (const char* uri, request& req);

    bool
    send_request (request& what);

    unsigned int
    get_remaining (void)
    {
      return remaining_;
    }

    unsigned int
    get_status_code (void)
    {
      return status_;
    }

    unsigned int
    get_content_len (void)
    {
      return content_len_;
    }

    bool
    chunked_transfer (void)
    {
      return chunked_transfer_;
    }

    bool
    more_data ()
    {
      return remaining_ || chunked_transfer_;
    }

    bool
    is_redirecting (void);

    bool
    is_success (void);

    void
    get_version (uint8_t& version_major, uint8_t& version_minor,
                 uint8_t& version_patch)
    {
      version_major = VERSION_MAJOR;
      version_minor = VERSION_MINOR;
      version_patch = VERSION_PATCH;
    }

  protected:

    virtual void
    on_close_internal (void);

    virtual void
    on_close (void);

    virtual void
    on_data ();  // data received callback; internal, should only be overloaded
                 // to call on_recv ()
    virtual void
    on_recv (uint8_t* buf, size_t cnt) = 0;

    virtual void
    on_open (void);  // called when opened

    virtual bool
    on_update (void); // called before reading from the socket

    // new ones:
    virtual void
    on_request_done (void)
    {
    }

    bool
    redirect (char* loc, bool forceGET);

    void
    process_chunk (void);

    bool
    open_request (const request& req);

    bool
    parse_header (void);

    void
    parse_header_fields (const char* s, size_t size);

    bool
    handle_status (void); // handle HTTP result status

    void
    finish_request (void);

    void
    on_recv_internal (uint8_t* buf, unsigned int size);

    static constexpr uint8_t VERSION_MAJOR = 0;
    static constexpr uint8_t VERSION_MINOR = 9;
    static constexpr uint8_t VERSION_PATCH = 5;

    // request attributes
    const char* user_agent_;
    const char* accept_encoding_; // default empty
    const char* content_type_;
    unsigned int keep_alive_;     // http related

    // answer attributes
    unsigned int content_len_;  // as reported by server
    unsigned int status_;       // http status code, HTTP_OK if things are good

    // http "Content-Length: X" - already recvd. 0 if ready for next packet.
    // for chunked transfer encoding, this holds the remaining size of the current chunk
    unsigned int remaining_;
    request cur_request_;

    bool in_progress_;
    bool chunked_transfer_;
    bool must_close_;    // keep-alive specified, or not
    bool follow_redir_;  // default true. Follow 3xx redirects if this is set.
    bool always_handle_; // also deliver to _OnRecv() if a non-success code was received.

    char header_buff_[REQUEST_HEADER_BUFFER_LEN]; // buffer to spool the request header
    char location_[REDIRECT_BUFFER_LEN]; // redirect URL
    char hostname_buff_[HOSTNAME_BUFFER_LEN];
    char protocol_[8]; // http or https
  };

} // end namespace micro_http_client

#endif
