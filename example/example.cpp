/*
 * example.cpp
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
 * Created on: 23 Jan. 2023 (LNP)
 */

#include <cmsis-plus/rtos/os.h>
#include <cmsis-plus/diag/trace.h>

#include "example.h"

#define PRINTF_ os::trace::printf

using namespace micro_http_client;

uint8_t buffer[4096];
uint8_t data[4096];

// instantiate a http-client class
http_client httpclnt
  { buffer, sizeof(buffer) };

const char github_url[] =
  { "https://github.com/lixpaulian/micro-http-client" };

const char github_url_redirect[] =
  { "http://github.com/lixpaulian/micro-http-client" };

const char reqbin_url[] =
  { "https://reqbin.com/echo/post/json" };

const char dowload_url[] =
      {
          "https://codeload.github.com/lixpaulian/micro-http-client/zip/refs/heads/main" };

const char post_req[] =
  { //
        "{ \
    \"Id\": 12345, \
    \"Customer\": \"John Doe\", \
    \"Quantity\": 1, \
    \"Price\": 10.00 \
  }" };

void
httptest (void)
{
  params_t pp;

  httpclnt.init ();

#if FILE_SYSTEM == true
  pp.f = nullptr;
#endif
  pp.buff = data;
  pp.buff_len = sizeof(data);
  pp.post = nullptr;

  PRINTF_ ("HTTPS GET test\n");
  pp.url = github_url;
  if (httpclnt.xfer (&pp))
    {
      PRINTF_ ("%s\n", data);
      PRINTF_ ("success\n");
    }
  else
    {
      PRINTF_ ("failed\n");
    }
  httpclnt.close ();

  PRINTF_ ("HTTPS GET with redirect test\n");
  pp.url = github_url_redirect;
  if (httpclnt.xfer (&pp))
    {
      PRINTF_ ("%s\n", data);
      PRINTF_ ("success\n");
    }
  else
    {
      PRINTF_ ("failed\n");
    }
  httpclnt.close ();

  PRINTF_ ("HTTPS POST test\n");
  pp.url = reqbin_url;
  pp.post = post_req;
  httpclnt.set_content_type ("application/json");
  if (httpclnt.xfer (&pp))
    {
      PRINTF_ ("%s\n", data);
      PRINTF_ ("success\n");
    }
  else
    {
      PRINTF_ ("failed\n");
    }
  httpclnt.close ();

#if FILE_SYSTEM == true
  PRINTF_ ("download a file and save it on the file system\n");
  if ((pp.f = os::posix::open ("/flash/main.zip", O_WRONLY | O_CREAT))
      == nullptr)
    {
      PRINTF_ ("failed to open the target file\n");
    }
  else
    {
      pp.url = dowload_url;
      pp.post = nullptr;
      if (httpclnt.xfer (&pp))
        {
          PRINTF_ ("success\n");
        }
      else
        {
          PRINTF_ ("failed\n");
        }
      pp.f->close ();
      httpclnt.close ();
    }
#endif
}
