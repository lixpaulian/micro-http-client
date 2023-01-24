/*
 * http-client.h
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
 * Created on: 18 Jan 2023 (LNP)
 */

#ifndef EXAMPLE_HTTP_CLIENT_H_
#define EXAMPLE_HTTP_CLIENT_H_

#include "http-engine.h"

#define FILE_SYSTEM true

#if FILE_SYSTEM == true
#include <cmsis-plus/posix-io/file-system.h>
#include <cmsis-plus/posix-io/file.h>
#include <fcntl.h>
#endif

namespace micro_http_client
{

  typedef struct
  {
    const char* url;
    const char* post;
    uint8_t* buff;
    size_t buff_len;
#if FILE_SYSTEM == true
    os::posix::io* f;
#endif
  } params_t;

  // create a new class from http_socket to suit your needs (set-up parameters,
  // handle call-backs, etc.)

  class http_client : public http_socket
  {
  public:

    http_client (uint8_t* buff, size_t len);

    virtual
    ~http_client ();

    void
    init (void);

    bool
    xfer (params_t* pp);

    bool
    not_ready (void);

  private:

    virtual void
    on_close ();

    virtual void
    on_open ();

    virtual void
    on_request_done ();

    virtual void
    on_recv (uint8_t* buf, size_t cnt);

    uint8_t* buff_;
    size_t buff_len_;
#if FILE_SYSTEM == true
    os::posix::io* f_;
#endif
    bool finished_;

  };

}

#endif /* EXAMPLE_HTTP_CLIENT_H_ */
