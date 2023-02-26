/*
 * http-engine.cpp
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

#include <cmsis-plus/rtos/os.h>
#include <cmsis-plus/diag/trace.h>
#include <assert.h>

#include "http-engine.h"

#define INVALID_SOCKET (SOCKET)(~0)
#define SOCKETVALID(s) ((s) != INVALID_SOCKET)

using namespace os;

namespace micro_http_client
{

#if STATIC_SSL_CONTEXT == true
  // statically instantiate the SSL context
  ssl_context ssl_ctx
    { };
#endif

  //----------------------------------------------------------------------------

  ssl_context::ssl_context (void)
  {
    mbedtls_entropy_init (&entropy);
    mbedtls_x509_crt_init (&cacert);
    mbedtls_ssl_init (&ssl);
    mbedtls_ctr_drbg_init (&ctr_drbg);
    mbedtls_ssl_config_init (&conf);
  }

  ssl_context::~ssl_context (void)
  {
    mbedtls_entropy_free (&entropy);
    mbedtls_x509_crt_free (&cacert);
    mbedtls_ssl_free (&ssl);
    mbedtls_ctr_drbg_free (&ctr_drbg);
    mbedtls_ssl_config_free (&conf);
  }

  int
  ssl_context::init (void)
  {
    const char* pers = "the quick brown fox";
    const size_t perslen = strlen (pers);
    int err;

    do
      {
        err = mbedtls_ctr_drbg_seed (&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char*) pers, perslen);
        if (err)
          {
#if HTTPC_DEBUG > 0
            trace::printf ("%s(): mbedtls_ctr_drbg_seed() returned %d\n",
                           __func__, err);
#endif
            break;
          }

        err = mbedtls_ssl_config_defaults (&conf, //
            MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_STREAM,
            MBEDTLS_SSL_PRESET_DEFAULT);
        if (err)
          {
#if HTTPC_DEBUG > 0
            trace::printf ("%s(): mbedtls_ssl_config_defaults() returned %d\n",
                           __func__, err);
#endif
            break;
          }

        mbedtls_ssl_conf_authmode (&conf, MBEDTLS_SSL_VERIFY);
        mbedtls_ssl_conf_ca_chain (&conf, &cacert, NULL);

        /* SSLv3, TLS 1.0 and 1.1 are deprecated, minimum should be TLS 1.2 */
        /* TODO: Due to the old update server currently set to TLS 1.0 */
        mbedtls_ssl_conf_min_version (&conf, MBEDTLS_SSL_MAJOR_VERSION,
        MBEDTLS_SSL_MINOR_VERSION);

        mbedtls_ssl_conf_rng (&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
        mbedtls_ssl_conf_dbg (&conf, nullptr, nullptr); // no debug

        err = mbedtls_ssl_setup (&ssl, &conf);
        if (err)
          {
#if HTTPC_DEBUG > 0
            trace::printf ("%s(): mbedtls_ssl_setup returned %d\n", __func__,
                           err);
#endif
          }
      }
    while (0);

    return err;
  }

  void
  ssl_context::reset (void)
  {
    mbedtls_ssl_session_reset (&ssl);
  }

  //----------------------------------------------------------------------------

  tcp_socket::tcp_socket (uint8_t* buff, size_t len) :
      inbuf_
        { buff }, //
      inbuf_size_
        { len }
  {
    s_ = INVALID_SOCKET;
    nonblocking_ = true;
    last_port_ = 0;
    recv_size_ = 0;
    write_size_ = len - 1;
    readptr_ = writeptr_ = inbuf_;
    last_host_ = nullptr;
    ssl_inited_ = false;
    use_ssl_ = false;
    certs_ = nullptr;
    append_ = false;
    mbedtls_error_ = 0;

#if STATIC_SSL_CONTEXT == true
    ctx_ = &ssl_ctx;
#else
    ctx_ = nullptr;
#endif
  }

  tcp_socket::~tcp_socket ()
  {
    close ();
  }

  bool
  tcp_socket::is_open (void)
  {
    return SOCKETVALID(s_);
  }

  void
  tcp_socket::close (void)
  {
    if (SOCKETVALID(s_))
      {
#if HTTPC_DEBUG > 0
        trace::printf ("%s()\n\n", __func__);
#endif

        on_close_internal ();

        if (use_ssl_)
          {
#if STATIC_SSL_CONTEXT == true
            ctx_->reset ();
#else
            delete ctx_;
            ctx_ = nullptr;
#endif
          }
        mbedtls_net_free ((mbedtls_net_context*) &s_);

        s_ = INVALID_SOCKET;
        recv_size_ = 0;
      }
  }

  void
  tcp_socket::on_close_internal (void)
  {
    on_close ();
  }

  bool
  tcp_socket::set_non_blocking (bool nonblock)
  {
    nonblocking_ = nonblock;

    if (SOCKETVALID(s_))
      {
        if (nonblock)
          {
            mbedtls_error_ = mbedtls_net_set_nonblock (
                (mbedtls_net_context*) &s_);
          }
        else
          {
            mbedtls_error_ = mbedtls_net_set_block ((mbedtls_net_context*) &s_);
          }
      }

    return (mbedtls_error_ == 0);
  }

  bool
  tcp_socket::open_socket (SOCKET* ps, const char* host, unsigned port)
  {
    int s;
    char portstr[16];
    bool result;

    sprintf (portstr, "%d", port);
    mbedtls_error_ = mbedtls_net_connect ((mbedtls_net_context*) &s, host,
                                          portstr,
                                          MBEDTLS_NET_PROTO_TCP);
    if (mbedtls_error_)
      {
#if HTTPC_DEBUG > 0
        trace::printf ("%s(): net_connect(%s, %u) returned -0x%x\n", __func__,
                       host, port, -mbedtls_error_);
#endif
        result = false;
      }
    else
      {
        *ps = s;
        result = true;
      }

    return result;
  }

  bool
  tcp_socket::open_ssl (void* ps)
  {
    mbedtls_ssl_set_bio (&ctx_->ssl, (mbedtls_net_context*) ps,
                         mbedtls_net_send, mbedtls_net_recv, NULL);

#if HTTPC_DEBUG > 0
    trace::printf ("%s(): SSL handshake now...\n", __func__);
#endif

    while ((mbedtls_error_ = mbedtls_ssl_handshake (&ctx_->ssl)))
      {
        if (mbedtls_error_ != MBEDTLS_ERR_SSL_WANT_READ
            && mbedtls_error_ != MBEDTLS_ERR_SSL_WANT_WRITE)
          {
#if HTTPC_DEBUG > 0
            trace::printf ("%s(): ssl_handshake returned -0x%x\n", __func__,
                           -mbedtls_error_);
#endif
            return false;
          }
      }
#if HTTPC_DEBUG > 0
    trace::printf ("%s(): SSL handshake done\n", __func__);
#endif

    return true;
  }

  bool
  tcp_socket::open (const char* host, unsigned int port, bool useSSL)
  {
    if (is_open ())
      {
        if ((host && strncmp (host, last_host_, strlen (host)))
            || (port && port != last_port_))
          {
#if HTTPC_DEBUG > 0
            trace::printf ("%s(): new host/port, must close and reopen\n",
                           __func__);
#endif
            close (); // ... and continue connecting to new host/port
          }
        else
          {
#if HTTPC_DEBUG > 0
            trace::printf ("%s(): already opened, re-use\n", __func__);
#endif
            return true; // still connected, to same host and port.
          }
      }

    if (host)
      {
        last_host_ = host;
      }
    else
      {
        host = last_host_;
      }

    if (port)
      {
        last_port_ = port;
      }
    else
      {
        port = last_port_;
        if (!port)
          {
#if HTTPC_DEBUG > 0
            trace::printf ("%s(): failed, bad port %d\n", __func__, port);
#endif
            return false;
          }
      }

    if (useSSL)
      {
#if STATIC_SSL_CONTEXT == true
        if (ssl_inited_ == false)
          {
            // one-time SSL init
            if (init_ssl (certs_) == false)
              {
#if HTTPC_DEBUG > 0
                trace::printf ("%s(): failed to init SSL\n", __func__);
#endif
                return false;
              }
            ssl_inited_ = true;
          }
#else
        ctx_ = new ssl_context ();
        if (init_ssl (certs_) == false)
          {
#if HTTPC_DEBUG > 0
            trace::printf ("%s(): failed to init SSL\n", __func__);
#endif
            delete ctx_;
            ctx_ = nullptr;
            return false;
          }
#endif
        // hostname set here should match CN in server certificate
        mbedtls_ssl_set_hostname (&ctx_->ssl, host);
      }
    use_ssl_ = useSSL;
    recv_size_ = 0;

    assert(!SOCKETVALID(s_));

    SOCKET s;
    if (!open_socket (&s, host, port))
      {
#if HTTPC_DEBUG > 0
        trace::printf ("%s(): failed\n", __func__);
#endif
        return false;
      }
    s_ = s;

    // restore setting if it was set in invalid state. static call
    // because s_ is intentionally still invalid here.
    set_non_blocking (nonblocking_);

    if (useSSL)
      {
        if (!open_ssl (&s_))
          {
#if HTTPC_DEBUG > 0
            trace::printf ("%s(): open ssl failed\n", __func__);
#endif
            close ();
            return false;
          }
      }

    on_open ();

#if HTTPC_DEBUG > 0
    trace::printf ("%s(): success\n", __func__);
#endif

    return true;
  }

  bool
  tcp_socket::init_ssl (const char* certs)
  {
    bool result = false;

    if (ctx_)
      {
        if ((mbedtls_error_ = ctx_->init ()) == 0)
          {
            if (certs)
              {
                mbedtls_error_ = mbedtls_x509_crt_parse (
                    &ctx_->cacert, (const unsigned char*) certs,
                    strlen (certs) + 1);
                if (mbedtls_error_)
                  {
                    ctx_->reset ();
#if HTTPC_DEBUG > 0
                    trace::printf ("%s(): x509_crt_parse() returned -0x%x\n",
                                   __func__, -mbedtls_error_);
#endif
                  }
                else
                  {
                    result = true;
                  }
              }
          }
      }

    return result;
  }

  void
  tcp_socket::set_certs (const char* certs)
  {
    certs_ = certs;
  }

  tcp_socket::ssl_result_t
  tcp_socket::verify_ssl (char* buf, unsigned bufsize)
  {
    if (use_ssl_)
      {
        return SSLR_NO_SSL;
      }

    unsigned r = SSLR_OK;
    int res = mbedtls_ssl_get_verify_result (&ctx_->ssl);
    if (res)
      {
        if (res & MBEDTLS_X509_BADCERT_EXPIRED)
          {
            r |= SSLR_CERT_EXPIRED;
          }

        if (res & MBEDTLS_X509_BADCERT_REVOKED)
          {
            r |= SSLR_CERT_REVOKED;
          }

        if (res & MBEDTLS_X509_BADCERT_CN_MISMATCH)
          {
            r |= SSLR_CERT_CN_MISMATCH;
          }

        if (res & MBEDTLS_X509_BADCERT_NOT_TRUSTED)
          {
            r |= SSLR_CERT_NOT_TRUSTED;
          }

        if (res & MBEDTLS_X509_BADCERT_MISSING)
          {
            r |= SSLR_CERT_MISSING;
          }

        if (res & MBEDTLS_X509_BADCERT_SKIP_VERIFY)
          {
            r |= SSLR_CERT_SKIP_VERIFY;
          }

        if (res & MBEDTLS_X509_BADCERT_FUTURE)
          {
            r |= SSLR_CERT_FUTURE;
          }

        // More than just this?
        if (res
            & (MBEDTLS_X509_BADCERT_SKIP_VERIFY
                | MBEDTLS_X509_BADCERT_NOT_TRUSTED))
          {
            r |= SSLR_FAIL;
          }
      }

    if (buf && bufsize)
      {
        mbedtls_x509_crt_verify_info (buf, bufsize, "", res);
      }

    return (ssl_result_t) r;
  }

  bool
  tcp_socket::send_bytes (const void* str, unsigned int len)
  {
    if (!len)
      {
        return true;
      }

    if (!SOCKETVALID(s_))
      {
        return false;
      }

    unsigned int written = 0;
    while (true)
      {
        int ret = write_bytes ((const unsigned char*) str + written,
                               len - written);
        if (ret > 0)
          {
            assert((unsigned int )ret <= len);
            written += ret;
            if (written >= len)
              {
                break;
              }
          }
        else if (ret < 0)
          {
#if HTTPC_DEBUG > 0
            mbedtls_error_ = ret == -1 ? errno : ret;
            trace::printf ("%s(): error -0x%x\n", __func__, -mbedtls_error_);
#endif
            close ();
            return false;
          }
        // and if ret == 0, keep trying.
      }

    assert(written == len);

    return true;
  }

  int
  tcp_socket::write_bytes (const unsigned char* buf, size_t len)
  {
    int ret = 0;
    int err;

    if (use_ssl_)
      {
        err = mbedtls_ssl_write (&ctx_->ssl, buf, len);
      }
    else
      {
        err = mbedtls_net_send (&s_, buf, len);
      }

    switch (err)
      {
      case MBEDTLS_ERR_SSL_WANT_WRITE:
      case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
      case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
        ret = 0; // nothing written, try again later
        break;

      default:
        ret = err;
      }

    return ret;
  }

  void
  tcp_socket::shift_buffer (void)
  {
    size_t by = readptr_ - inbuf_;
    memmove (inbuf_, readptr_, by);
    readptr_ = inbuf_;
    writeptr_ = inbuf_ + by;
    write_size_ = inbuf_size_ - by - 1;
  }

  void
  tcp_socket::on_data (void)
  {
    on_recv (readptr_, recv_size_);
  }

  int
  tcp_socket::read_bytes (unsigned char* buf, size_t maxlen)
  {
    if (use_ssl_)
      {
        return mbedtls_ssl_read (&ctx_->ssl, buf, maxlen);
      }
    else
      {
        return mbedtls_net_recv (&s_, buf, maxlen);
      }
  }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough="

  bool
  tcp_socket::update (void)
  {
    if (!on_update ())
      {
        return false;
      }

    if (!is_open ())
      {
        return false;
      }

    if (!inbuf_)
      {
        return false;
      }

    if (append_ == false)
      {
        // reset pointers
        write_size_ = inbuf_size_ - 1;
        readptr_ = writeptr_ = inbuf_;
        recv_size_ = 0;
      }
    // else continue to fill the buffer from where the previous read left
    int bytes = read_bytes (writeptr_ + recv_size_, write_size_ - recv_size_);
    if (bytes > 0) // we received something
      {
#if HTTPC_DEBUG > 2
        trace::printf ("%s (%d): %.*s\n", __func__, bytes, bytes, writeptr_);
#endif
        recv_size_ += bytes;
        inbuf_[recv_size_] = '\0';
        on_data ();
      }
    else if (bytes == 0) // remote has closed the connection
      {
#if HTTPC_DEBUG > 0
        if (append_)
          {
            trace::printf (
                "%s(): incoming buffer overflowed, should be increased\n",
                __func__);
          }
#endif
        close ();
      }
    else // whoops, error?
      {
        // possible that the error is returned directly (in that case,
        // < -1, or -1 is returned and the error has to be retrieved separately.
        mbedtls_error_ = bytes == -1 ? errno : bytes;
        switch (mbedtls_error_)
          {
          case EWOULDBLOCK:
            return false;

          case MBEDTLS_ERR_SSL_WANT_READ:
            break; // try again later

          default:
#if HTTPC_DEBUG > 0
            trace::printf ("%s(): error -0x%x\n", __func__, -mbedtls_error_);
#endif
            /* no break */
          case ECONNRESET:
          case ENOTCONN:
          case ETIMEDOUT:
            close ();
            break;
          }
      }

    return true;
  }

  //----------------------------------------------------------------------------

  http_socket::http_socket (uint8_t* buff, size_t len) :
      tcp_socket (buff, len)
  {
    keep_alive_ = 0;
    content_len_ = 0;
    content_type_ = nullptr;
    status_ = 0;
    user_agent_ = nullptr;
    accept_encoding_ = nullptr;
    follow_redir_ = true;
    always_handle_ = false;
    chunked_transfer_ = false;
    remaining_ = 0;
    must_close_ = true;
    in_progress_ = false;
  }

  http_socket::~http_socket ()
  {
  }

  void
  http_socket::on_open (void)
  {
    tcp_socket::on_open ();
    chunked_transfer_ = false;
    must_close_ = true;
  }

  void
  http_socket::on_close_internal (void)
  {
    if (!is_redirecting () || always_handle_)
      {
        on_close ();
      }
  }

  bool
  http_socket::on_update (void)
  {
    if (!tcp_socket::on_update ())
      {
        return false;
      }

    if (in_progress_ && !chunked_transfer_ && !remaining_ && status_)
      {
        finish_request ();
      }

    // initiate transfer if queue is not empty, but the socket somehow forgot to proceed
    if (!remaining_ && !chunked_transfer_ && !in_progress_)
      {
        finish_request ();
      }

    return true;
  }

  bool
  http_socket::transaction (const char* url, char* extra_header,
                            const char* post, size_t post_len)
  {
    request req;
    memset (&req, 0, sizeof(request));

    if (post)
      {
        req.post = post;
        req.post_len = post_len;
      }

    split_uri (url, req);
    if (is_redirecting () && req.host[0] == '\0')
      {
        // if we're following a redirection to the same host,
        // the server is likely to omit its hostname
        req.host = cur_request_.host;
      }
    if (extra_header)
      {
        req.extra_header = extra_header;
      }
    status_ = 0;
    in_progress_ = false;
    append_ = false;

    return send_request (req);
  }

  bool
  http_socket::redirect (char* loc, bool forceGET)
  {
    bool result = false;

#if HTTPC_DEBUG > 0
    trace::printf ("%s(): following HTTP redirect to: %s\n", __func__, loc);
#endif

    if (loc)
      {
        request req;
        memset (&req, 0, sizeof(request));
        req.useSSL = cur_request_.useSSL;
        if (!forceGET)
          {
            req.post = cur_request_.post;
          }
        split_uri (loc, req);
        if (!req.protocol) // assume local resource
          {
            req.host = cur_request_.host;
            req.resource = loc;
          }
        if (!req.host)
          {
            req.host = cur_request_.host;
          }
        req.extra_header = cur_request_.extra_header;

        in_progress_ = false;
        remaining_ = 0;

        result = send_request (req);
      }

    return result;
  }

  bool
  http_socket::split_uri (const char* uri, request& req)
  {
    static char slash[] =
      { "/" };
    const char* p = uri;
    req.port = 80;      // set a default
    bool ssl = false;
    char* sl = strstr (p, "//");

    if (sl)
      {
        char* colon = strchr (p, ':');
        char* firstslash = strchr (p, '/');
        if (colon < firstslash)
          {
            memset (protocol_, 0, sizeof(protocol_));
            strncpy (protocol_, p, (sl - p - 1));
            req.protocol = protocol_;
          }

        if (strncmp (p, "http://", 7) == 0)
          {
            req.port = 80;
          }
        else if (strncmp (p, "https://", 8) == 0)
          {
            req.port = 443;
            ssl = true;
          }
        else
          {
            return false;
          }
        p = sl + 2;
      }

    memset (hostname_buff_, 0, sizeof(hostname_buff_));
    sl = strchr (p, '/');       // sl should point on the '/' of the resource
    if (!sl)
      {
        strncpy (hostname_buff_, p, sizeof(hostname_buff_));
        req.resource = slash;
      }
    else
      {
        strncpy (hostname_buff_, p, sl - p);
        req.resource = sl;
      }
    req.host = hostname_buff_;

    char* colon = strchr (hostname_buff_, ':');
    if (colon != nullptr)
      {
        *colon = '\0';
        colon++;
        req.port = atoi (colon);
      }
    req.useSSL = ssl;

    return true;
  }

  bool
  http_socket::send_request (request& req)
  {
    bool result = false;

    if (req.host[0] != '\0' && req.port)
      {

        memset (header_buff_, 0, sizeof(header_buff_));

        int count = snprintf (header_buff_, sizeof(header_buff_),
                              "%s%s HTTP/1.1\r\n"
                              "Host: %s\r\n",
                              req.post ? "POST " : "GET ", req.resource,
                              req.host);

        if (keep_alive_)
          {
            count += snprintf (
                header_buff_ + count, sizeof(header_buff_) - count,
                "Connection: keep-alive\r\nKeep-Alive: timeout=%d, max=100\r\n",
                keep_alive_);
          }
        else
          {
            count += snprintf (header_buff_ + count,
                               sizeof(header_buff_) - count,
                               "Connection: close\r\n");
          }

        if (user_agent_)
          {
            count += snprintf (header_buff_ + count,
                               sizeof(header_buff_) - count,
                               "User-Agent: %s\r\nAccept: */*\r\n",
                               user_agent_);
          }

        if (accept_encoding_)
          {
            count += snprintf (header_buff_ + count,
                               sizeof(header_buff_) - count,
                               "Accept-Encoding: %s\r\n", accept_encoding_);
          }

        if (req.post)
          {
            count += snprintf (header_buff_ + count,
                               sizeof(header_buff_) - count,
                               "Content-Length: %d\r\nContent-Type: %s\r\n",
                               req.post_len, content_type_);
          }

        count += snprintf (header_buff_ + count, sizeof(header_buff_) - count,
                           "\r\n");

#if HTTPC_DEBUG > 1
        trace::printf ("%s(): %s", __func__, header_buff_);
#endif

        req.header = header_buff_;

        if (open_request (req))
          {
            result = send_bytes (req.header, strlen (req.header));
            if (result && req.post)      // POST?
              {
                result = send_bytes (req.post, req.post_len); // send POST content
              }
            in_progress_ = result;
          }
      }

    return result;
  }

  bool
  http_socket::open_request (const request& req)
  {
    bool result = false;

    if (in_progress_)
      {
#if HTTPC_DEBUG > 0
        trace::printf ("%s(): _inProgress == true, should not be called\n",
                       __func__);
#endif
      }
    else if (open (req.host, req.port, req.useSSL))
      {
        in_progress_ = true;
        cur_request_ = req;
        result = true;
      }

    return result;
  }

  void
  http_socket::finish_request (void)
  {
    if (in_progress_)
      {
        if (!is_redirecting () || always_handle_)
          {
            on_request_done (); // notify about finished request
          }
        in_progress_ = false;
        if (must_close_)
          {
            close ();
          }
      }
  }

  void
  http_socket::process_chunk (void)
  {
    unsigned int chunksize = -1;

    if (!chunked_transfer_)
      {
        return;
      }

    while (true)
      {
        // less data required until chunk end than received, means the new chunk
        // starts somewhere in the middle of the received data block.
        // finish this chunk first.
        if (remaining_)
          {
            if (remaining_ <= recv_size_)
              {
                // it contains the rest of the chunk, including CRLF
                on_recv_internal (readptr_, remaining_ - 2); // implicitly skip CRLF
                readptr_ += remaining_;
                recv_size_ -= remaining_;
                remaining_ = 0; // done with this one.
                if (!chunksize) // and if chunksize was 0, we are done with all chunks.
                  {
                    break;
                  }
              }
            else // buffer did not yet arrive completely
              {
                on_recv_internal (readptr_, recv_size_);
                remaining_ -= recv_size_;
                recv_size_ = 0; // done with the whole buffer, but not with the chunk
                return;
              }
          }

        // each chunk identifier ends with CRLF.
        // if we don't find that, we hit the corner case that the chunk identifier
        // was not fully received; in that case, adjust the buffer and wait
        // for the rest of the data to be appended
        char* term = strstr ((char*) readptr_, "\r\n");
        if (!term)
          {
            if (recv_size_)
              {
                // if there is still something queued, move it to the left of
                // the buffer and append on next read
                shift_buffer ();
              }
            return;
          }
        term += 2; // skip CRLF

        // when we are here, the (next) chunk header was completely received.
        chunksize = strtoul ((char*) readptr_, NULL, 16);

        // the http protocol specifies that each chunk has a trailing CRLF
        remaining_ = chunksize + 2;
        recv_size_ -= ((uint8_t*) term - readptr_);
        readptr_ = (uint8_t*) term;
      }

    if (!chunksize)
      {
        // this was the last chunk, no further data expected unless requested
        chunked_transfer_ = false;
        finish_request ();
#if HTTPC_DEBUG > 0
        if (recv_size_)
          {
            trace::printf (
                "%s(): there are %u bytes left in the buffer, huh?\n", __func__,
                recv_size_);
          }
#endif
        if (must_close_)
          {
            close ();
          }
      }
  }

  void
  http_socket::parse_header_fields (const char* s, size_t size)
  {
    must_close_ = false; // set defaults
    location_[0] = '\0';

    // Key: Value data\r\n
    const char* const maxs = s + size;
    while (s < maxs)
      {
        while (isspace (*s))
          {
            ++s;
            if (s >= maxs)
              {
                return;
              }
          }
        const char* const colon = strchr (s, ':');
        if (!colon)
          {
            return;
          }

        char* valEnd = strchr (colon, '\n'); // last char of val data
        if (!valEnd)
          {
            return;
          }

        while (valEnd[-1] == '\n' || valEnd[-1] == '\r')
          {
            // skip backwards if necessary
            --valEnd;
          }

        const char* val = colon + 1; // value starts after ':' ...
        while (isspace (*val) && val < valEnd)
          {
            // skip spaces after the colon
            ++val;
          }

#if HTTPC_DEBUG > 1
        trace::printf ("%s(): %.*s: %.*s\n", __func__, colon - s, s,
                       valEnd - val, val);
#endif
        char tmp;
        if (!strncasecmp (s, "content-length", strlen ("content-length")))
          {
            tmp = *valEnd;
            *valEnd = '\0';
            content_len_ = atoi (val);
            *valEnd = tmp;
          }
        else if (!strncasecmp (s, "connection", strlen ("connection")))
          {
            must_close_ = (strncasecmp (val, "close", strlen ("close")) == 0);
          }
        else if (!strncasecmp (s, "transfer-encoding",
                               strlen ("transfer-encoding")))
          {
            chunked_transfer_ = (strncasecmp (val, "chunked",
                                              strlen ("chunked")) == 0);
          }
        else if (!strncasecmp (s, "location", strlen ("location")))
          {
            tmp = *valEnd;
            *valEnd = '\0';
            strncpy (location_, val, sizeof(location_));
            *valEnd = tmp;
          }
        s = valEnd;
      }
  }

  bool
  http_socket::handle_status (void)
  {
    bool result = false;
    remaining_ = content_len_;

    // as per the spec, we also need to handle 1xx codes, but are free to ignore them
    const bool success = is_success () || (status_ >= 100 && status_ <= 199);

#if HTTPC_DEBUG > 0
    if (!(chunked_transfer_ || content_len_) && success)
      {
        trace::printf (
            "%s(): not chunked transfer and content-length==0, this will fail\n",
            __func__);
      }
    trace::printf ("%s(): got HTTP status %d\n", __func__, status_);
#endif

    if (success)
      {
        result = true;
      }
    else
      {
        bool forceGET = false;
        switch (status_)
          {
          case 303:
            forceGET = true; // as per spec, continue with a GET request
            /* no break */
          case 301:
          case 302:
          case 307:
          case 308:
            if (follow_redir_)
              {
                if (*location_ != '\0')
                  {
                    result = redirect (location_, forceGET);
                  }
              }
            break;

          default:
            break;
          }
      }

    return result;
  }

#pragma GCC diagnostic pop

  bool
  http_socket::is_redirecting (void)
  {
    switch (status_)
      {
      case 301:
      case 302:
      case 303:
      case 307:
      case 308:
        return true;
      }
    return false;
  }

  bool
  http_socket::is_success (void)
  {
    return status_ >= 200 && status_ <= 205;
  }

  bool
  http_socket::parse_header (void)
  {
    bool result = false;
    const char* hptr = (const char*) inbuf_;

    do
      {
        if ((recv_size_ >= 5 || strlen (hptr) >= 5)
            && memcmp ("HTTP/", hptr, 5))
          {
#if HTTPC_DEBUG > 0
            trace::printf ("%s(): not a HTTP stream\n", __func__);
#endif
            break;
          }

        const char* hdrend = strstr (hptr, "\r\n\r\n");
        if (!hdrend)
          {
            // incomplete header, try to get more from the socket
            append_ = true;
            break;
          }
        append_ = false;

#if HTTPC_DEBUG > 1
        trace::printf ("%s(): incoming header length %d\n", __func__,
                       hdrend - hptr);
#endif

#if HTTPC_DEBUG > 2
        trace::printf ("%s(): %s", __func__, hptr);
#endif

        hptr = strchr (hptr + 5, ' '); // skip "HTTP/", already known
        if (!hptr)
          {
            break; // WTF?
          }

        ++hptr; // number behind first space is the status code
        status_ = atoi (hptr);

        // default values
        chunked_transfer_ = false;
        content_len_ = 0; // yet unknown

        hptr = strstr (hptr, "\r\n");
        parse_header_fields (hptr + 2, hdrend - hptr);

        if (handle_status ())
          {
            // get ready; skip double newline, must have been found in hptr earlier.
            readptr_ = (uint8_t*) strstr ((char*) inbuf_, "\r\n\r\n") + 4;
            recv_size_ -= (readptr_ - inbuf_); // skip the header part
            result = true;
          }
        // else bail out on handle_status () failure
      }
    while (0);

    return result;
  }

  // generic http header parsing
  void
  http_socket::on_data (void)
  {
    if (!(chunked_transfer_ || (remaining_ && recv_size_)))
      {
        if (parse_header () == false)
          {
            status_ = 0;
            return;     // here we bail out
          }
      }

    if (is_redirecting ())
      {
        status_ = 0;
        chunked_transfer_ = false;
      }
    else
      {
        if (chunked_transfer_)
          {
            process_chunk (); // first, try to finish one or more chunks
          }
        else if (remaining_ && recv_size_)
          {
            // something remaining? if so, we got a header earlier, but not all data
            remaining_ -= recv_size_;
            on_recv_internal (readptr_, recv_size_);

            if (int (remaining_) < 0)
              {
#if HTTPC_DEBUG > 0
                trace::printf ("%s(): _remaining wrap-around, huh??\n",
                               __func__);
#endif
                remaining_ = 0;
              }
            if (!remaining_) // received last block?
              {
                if (must_close_)
                  {
                    close ();
                  }
                else
                  {
                    finish_request ();
                  }
              }
            // nothing else to do here
          }
        // otherwise, the server sent just the header, with the data following
        // in the next packet
      }

    return;
  }

  void
  http_socket::on_close (void)
  {
    if (!more_data ())
      {
        finish_request ();
      }
  }

  void
  http_socket::on_recv_internal (uint8_t* buf, unsigned int size)
  {
    if (is_success () || always_handle_)
      {
        on_recv (buf, size);
      }
  }

} // namespace micro_http_client
