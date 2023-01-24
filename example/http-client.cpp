/*
 * http-client.cpp
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

#include <algorithm>
#include <string.h>

#include "http-client.h"

namespace micro_http_client
{

  /*
   * A "howto" on getting CA certificates can be found here:
   *
   *    https://os.mbed.com/docs/mbed-os/v5.15/tutorials/tls-tutorial.html
   */
  const char SSL_CA_PEM[] =

#if 1
      // Let's encrypt CA certificate
      "-----BEGIN CERTIFICATE-----\n"
          "MIIFYDCCBEigAwIBAgIQQAF3ITfU6UK47naqPGQKtzANBgkqhkiG9w0BAQsFADA/\n"
          "MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\n"
          "DkRTVCBSb290IENBIFgzMB4XDTIxMDEyMDE5MTQwM1oXDTI0MDkzMDE4MTQwM1ow\n"
          "TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\n"
          "cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwggIiMA0GCSqGSIb3DQEB\n"
          "AQUAA4ICDwAwggIKAoICAQCt6CRz9BQ385ueK1coHIe+3LffOJCMbjzmV6B493XC\n"
          "ov71am72AE8o295ohmxEk7axY/0UEmu/H9LqMZshftEzPLpI9d1537O4/xLxIZpL\n"
          "wYqGcWlKZmZsj348cL+tKSIG8+TA5oCu4kuPt5l+lAOf00eXfJlII1PoOK5PCm+D\n"
          "LtFJV4yAdLbaL9A4jXsDcCEbdfIwPPqPrt3aY6vrFk/CjhFLfs8L6P+1dy70sntK\n"
          "4EwSJQxwjQMpoOFTJOwT2e4ZvxCzSow/iaNhUd6shweU9GNx7C7ib1uYgeGJXDR5\n"
          "bHbvO5BieebbpJovJsXQEOEO3tkQjhb7t/eo98flAgeYjzYIlefiN5YNNnWe+w5y\n"
          "sR2bvAP5SQXYgd0FtCrWQemsAXaVCg/Y39W9Eh81LygXbNKYwagJZHduRze6zqxZ\n"
          "Xmidf3LWicUGQSk+WT7dJvUkyRGnWqNMQB9GoZm1pzpRboY7nn1ypxIFeFntPlF4\n"
          "FQsDj43QLwWyPntKHEtzBRL8xurgUBN8Q5N0s8p0544fAQjQMNRbcTa0B7rBMDBc\n"
          "SLeCO5imfWCKoqMpgsy6vYMEG6KDA0Gh1gXxG8K28Kh8hjtGqEgqiNx2mna/H2ql\n"
          "PRmP6zjzZN7IKw0KKP/32+IVQtQi0Cdd4Xn+GOdwiK1O5tmLOsbdJ1Fu/7xk9TND\n"
          "TwIDAQABo4IBRjCCAUIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw\n"
          "SwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vYXBwcy5pZGVudHJ1\n"
          "c3QuY29tL3Jvb3RzL2RzdHJvb3RjYXgzLnA3YzAfBgNVHSMEGDAWgBTEp7Gkeyxx\n"
          "+tvhS5B1/8QVYIWJEDBUBgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEB\n"
          "ATAwMC4GCCsGAQUFBwIBFiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQu\n"
          "b3JnMDwGA1UdHwQ1MDMwMaAvoC2GK2h0dHA6Ly9jcmwuaWRlbnRydXN0LmNvbS9E\n"
          "U1RST09UQ0FYM0NSTC5jcmwwHQYDVR0OBBYEFHm0WeZ7tuXkAXOACIjIGlj26Ztu\n"
          "MA0GCSqGSIb3DQEBCwUAA4IBAQAKcwBslm7/DlLQrt2M51oGrS+o44+/yQoDFVDC\n"
          "5WxCu2+b9LRPwkSICHXM6webFGJueN7sJ7o5XPWioW5WlHAQU7G75K/QosMrAdSW\n"
          "9MUgNTP52GE24HGNtLi1qoJFlcDyqSMo59ahy2cI2qBDLKobkx/J3vWraV0T9VuG\n"
          "WCLKTVXkcGdtwlfFRjlBz4pYg1htmf5X6DYO8A4jqv2Il9DjXA6USbW1FzXSLr9O\n"
          "he8Y4IWS6wY7bCkjCWDcRQJMEhg76fsO3txE+FiYruq9RUWhiF1myv4Q6W+CyBFC\n"
          "Dfvp7OOGAN6dEOM4+qR9sdjoSYKEBpsr6GtPAQw4dy753ec5\n"
          "-----END CERTIFICATE-----\n"

#endif

#if 1
      // Apple CA certificate
      "-----BEGIN CERTIFICATE-----\n"
      "MIIFMjCCBBqgAwIBAgIQBxd5EQBdImf2iJL2j4tQWDANBgkqhkiG9w0BAQsFADBs\n"
      "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n"
      "d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5j\n"
      "ZSBFViBSb290IENBMB4XDTIwMDQyOTEyNTQ1MFoXDTMwMDQxMDIzNTk1OVowUTEL\n"
      "MAkGA1UEBhMCVVMxEzARBgNVBAoTCkFwcGxlIEluYy4xLTArBgNVBAMTJEFwcGxl\n"
      "IFB1YmxpYyBFViBTZXJ2ZXIgUlNBIENBIDIgLSBHMTCCASIwDQYJKoZIhvcNAQEB\n"
      "BQADggEPADCCAQoCggEBAOIA/aXfX7k4cUnrupPYw00z3FwU6nAvwepTO8ueUcBU\n"
      "smQGppcx5BeEyngvZ8PSieH0GHHK7RnHbgLChyon2H9EpgYo7NQ1yrcC5THvo3Vr\n"
      "lAP6U746ORSDxUbbv4z15kAsyvABUCFi8S7IXkzDIjhOICNrA8fXUpUKbIccI2Jv\n"
      "Mz7Rvw5GeG7caa2u+vSI3TmBnwMcjVqlsScqY6tbE/ji7C/XDw7wUpMHyaQMVGPO\n"
      "7mJfi0/QbiUPWwnCJPYAqPpvBVjeBh0avUCGaP2ZtZc2Jns1C8h9ebJG+Z3awdgB\n"
      "qQPYD2I+fy/aBtnTOkhnBJti8jxh1ThNV65S9SucZecCAwEAAaOCAekwggHlMB0G\n"
      "A1UdDgQWBBRQVatDoa+pSCtawaKHiQTkeg7K2jAfBgNVHSMEGDAWgBSxPsNpA/i/\n"
      "RwHUmCYaCALvY2QrwzAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUH\n"
      "AwEGCCsGAQUFBwMCMBIGA1UdEwEB/wQIMAYBAf8CAQAwNAYIKwYBBQUHAQEEKDAm\n"
      "MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wSwYDVR0fBEQw\n"
      "QjBAoD6gPIY6aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0SGlnaEFz\n"
      "c3VyYW5jZUVWUm9vdENBLmNybDCB3AYDVR0gBIHUMIHRMIHFBglghkgBhv1sAgEw\n"
      "gbcwKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwgYoG\n"
      "CCsGAQUFBwICMH4MfEFueSB1c2Ugb2YgdGhpcyBDZXJ0aWZpY2F0ZSBjb25zdGl0\n"
      "dXRlcyBhY2NlcHRhbmNlIG9mIHRoZSBSZWx5aW5nIFBhcnR5IEFncmVlbWVudCBs\n"
      "b2NhdGVkIGF0IGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9ycGEtdWEwBwYFZ4EM\n"
      "AQEwDQYJKoZIhvcNAQELBQADggEBAKZebFC2ZVwrTj+u6nDo3O03e0/g/hN+6U5i\n"
      "A7X9dBGmQx3C7NkPNAV0mUoaklsceIBIQ/bC7utdgwnSKTnm5HdVipASyLloU7TP\n"
      "2jAtDQdAxBavmLnFwcwXBp6n17uLp+uPU4DZgubM96LyUQilUlYERbgu66rCK18j\n"
      "RmobDvFT8E71oU13o1Oe/1WUHFbTynRkKW73JDd2rZ21Pim7LEJVY3OcRmtYNHaM\n"
      "/lunYx1ZQ+0fw7Hc5J/xR7vlRiuyP+fJ9ucuDYupLg333Di5R7JZIfnX42ecX0Dd\n"
      "0wIeuFj0HBjH6c25FUov/Fa5Zjr0VPjmmgN6PnoMArUZXDkQe3M=\n"
      "-----END CERTIFICATE-----\n"
#endif

#if 1
      // Cloudflare CA certificate
      "-----BEGIN CERTIFICATE-----\n"
      "MIIDzTCCArWgAwIBAgIQCjeHZF5ftIwiTv0b7RQMPDANBgkqhkiG9w0BAQsFADBa\n"
      "MQswCQYDVQQGEwJJRTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJl\n"
      "clRydXN0MSIwIAYDVQQDExlCYWx0aW1vcmUgQ3liZXJUcnVzdCBSb290MB4XDTIw\n"
      "MDEyNzEyNDgwOFoXDTI0MTIzMTIzNTk1OVowSjELMAkGA1UEBhMCVVMxGTAXBgNV\n"
      "BAoTEENsb3VkZmxhcmUsIEluYy4xIDAeBgNVBAMTF0Nsb3VkZmxhcmUgSW5jIEVD\n"
      "QyBDQS0zMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEua1NZpkUC0bsH4HRKlAe\n"
      "nQMVLzQSfS2WuIg4m4Vfj7+7Te9hRsTJc9QkT+DuHM5ss1FxL2ruTAUJd9NyYqSb\n"
      "16OCAWgwggFkMB0GA1UdDgQWBBSlzjfq67B1DpRniLRF+tkkEIeWHzAfBgNVHSME\n"
      "GDAWgBTlnVkwgkdYzKz6CFQ2hns6tQRN8DAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0l\n"
      "BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBIGA1UdEwEB/wQIMAYBAf8CAQAwNAYI\n"
      "KwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5j\n"
      "b20wOgYDVR0fBDMwMTAvoC2gK4YpaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL09t\n"
      "bmlyb290MjAyNS5jcmwwbQYDVR0gBGYwZDA3BglghkgBhv1sAQEwKjAoBggrBgEF\n"
      "BQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzALBglghkgBhv1sAQIw\n"
      "CAYGZ4EMAQIBMAgGBmeBDAECAjAIBgZngQwBAgMwDQYJKoZIhvcNAQELBQADggEB\n"
      "AAUkHd0bsCrrmNaF4zlNXmtXnYJX/OvoMaJXkGUFvhZEOFp3ArnPEELG4ZKk40Un\n"
      "+ABHLGioVplTVI+tnkDB0A+21w0LOEhsUCxJkAZbZB2LzEgwLt4I4ptJIsCSDBFe\n"
      "lpKU1fwg3FZs5ZKTv3ocwDfjhUkV+ivhdDkYD7fa86JXWGBPzI6UAPxGezQxPk1H\n"
      "goE6y/SJXQ7vTQ1unBuCJN0yJV0ReFEQPaA1IwQvZW+cwdFD19Ae8zFnWSfda9J1\n"
      "CZMRJCQUzym+5iPDuI9yP+kHyCREU3qzuWFloUwOxkgAyXVjBYdwRVKD05WdRerw\n"
      "6DEdfgkfCv4+3ao8XnTSrLE=\n"
      "-----END CERTIFICATE-----\n"
#endif

#if 1
      // Github CA certificate
      "-----BEGIN CERTIFICATE-----\n"
      "MIIEFzCCAv+gAwIBAgIQB/LzXIeod6967+lHmTUlvTANBgkqhkiG9w0BAQwFADBh\n"
      "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n"
      "d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD\n"
      "QTAeFw0yMTA0MTQwMDAwMDBaFw0zMTA0MTMyMzU5NTlaMFYxCzAJBgNVBAYTAlVT\n"
      "MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxMDAuBgNVBAMTJ0RpZ2lDZXJ0IFRMUyBI\n"
      "eWJyaWQgRUNDIFNIQTM4NCAyMDIwIENBMTB2MBAGByqGSM49AgEGBSuBBAAiA2IA\n"
      "BMEbxppbmNmkKaDp1AS12+umsmxVwP/tmMZJLwYnUcu/cMEFesOxnYeJuq20ExfJ\n"
      "qLSDyLiQ0cx0NTY8g3KwtdD3ImnI8YDEe0CPz2iHJlw5ifFNkU3aiYvkA8ND5b8v\n"
      "c6OCAYIwggF+MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFAq8CCkXjKU5\n"
      "bXoOzjPHLrPt+8N6MB8GA1UdIwQYMBaAFAPeUDVW0Uy7ZvCj4hsbw5eyPdFVMA4G\n"
      "A1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwdgYI\n"
      "KwYBBQUHAQEEajBoMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5j\n"
      "b20wQAYIKwYBBQUHMAKGNGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdp\n"
      "Q2VydEdsb2JhbFJvb3RDQS5jcnQwQgYDVR0fBDswOTA3oDWgM4YxaHR0cDovL2Ny\n"
      "bDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0R2xvYmFsUm9vdENBLmNybDA9BgNVHSAE\n"
      "NjA0MAsGCWCGSAGG/WwCATAHBgVngQwBATAIBgZngQwBAgEwCAYGZ4EMAQICMAgG\n"
      "BmeBDAECAzANBgkqhkiG9w0BAQwFAAOCAQEAR1mBf9QbH7Bx9phdGLqYR5iwfnYr\n"
      "6v8ai6wms0KNMeZK6BnQ79oU59cUkqGS8qcuLa/7Hfb7U7CKP/zYFgrpsC62pQsY\n"
      "kDUmotr2qLcy/JUjS8ZFucTP5Hzu5sn4kL1y45nDHQsFfGqXbbKrAjbYwrwsAZI/\n"
      "BKOLdRHHuSm8EdCGupK8JvllyDfNJvaGEwwEqonleLHBTnm8dqMLUeTF0J5q/hos\n"
      "Vq4GNiejcxwIfZMy0MJEGdqN9A57HSgDKwmKdsp33Id6rHtSJlWncg+d0ohP/rEh\n"
      "xRqhqjn1VtvChMQ1H3Dau0bwhr9kAMQ+959GG50jBbl9s08PqUU643QwmA==\n"
      "-----END CERTIFICATE-----\n"

#endif
  ;

  //----------------------------------------------------------------------------

  http_client::http_client (uint8_t* buff, size_t len) :
      http_socket (buff, len)
  {
    buff_ = nullptr;
    buff_len_ = 0;
#if FILE_SYSTEM == true
    f_ = nullptr;
#endif
    finished_ = false;
    set_certs (SSL_CA_PEM);
  }

  http_client::~http_client ()
  {
  }

  void
  http_client::init (void)
  {
    // you may want to set here the http parameters as you see fit
    set_keep_alive (5);
    set_non_blocking (false);
    set_user_agent ("micro_http_client");
    set_folllow_redirect (true);
    set_always_handle (true);
  }

  bool
  http_client::xfer (params_t* pp)
  {
    bool result = false;
    buff_ = pp->buff;
    buff_len_ = pp->buff_len - 1;
#if FILE_SYSTEM == true
    f_ = pp->f;
#endif
    finished_ = false;

    if ((result = transaction (pp->url, nullptr, pp->post, strlen (pp->post))))
      {
        while (not_ready ())
          {
            result = update ();
            if (result == false)
              {
                // an error occurred
                break;
              }
          }
      }

    return result;
  }

  bool
  http_client::not_ready (void)
  {
    return (more_data () || finished_ == false);
  }

  void
  http_client::on_close ()
  {
  }

  void
  http_client::on_open ()
  {
    buff_[0] = '\0';
  }

  void
  http_client::on_request_done ()
  {
    finished_ = true;
  }

  void
  http_client::on_recv (uint8_t* buf, size_t cnt)
  {
#if FILE_SYSTEM == true
    if (f_)
      {
        f_->write (buf, cnt); // TODO: should handle possible file system errors
      }
    else
#endif
      {
        if (buff_len_)
          {
            cnt = std::min (buff_len_, cnt);
            memcpy (buff_, buf, cnt);
            buff_ += cnt;
            buff_len_ -= cnt;
            *buff_ = 0;
          }
      }
  }

}
