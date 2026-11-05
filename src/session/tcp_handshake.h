#ifndef TP_TCP_HANDSHAKE_H
#define TP_TCP_HANDSHAKE_H

#include <cstdio>
#include <ctime>
#include <cstring>
#include <boost/asio/read.hpp>

#include "core/config.h"

inline tp::string make_plain_http_response(const tp::string& file_response, const tp::string& server) {
    if (!file_response.empty()) return file_response;
    std::time_t now = std::time(nullptr);
    std::tm utc{};
#ifdef _WIN32
    if (gmtime_s(&utc, &now) != 0) return {};
#else
    if (!gmtime_r(&now, &utc)) return {};
#endif
    static const char* weekdays[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    static const char* months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    char date[64];
    const int len = std::snprintf(date, sizeof(date), "%s, %02d %s %04d %02d:%02d:%02d GMT", weekdays[utc.tm_wday],
      utc.tm_mday, months[utc.tm_mon], utc.tm_year + 1900, utc.tm_hour, utc.tm_min, utc.tm_sec);
    if (len <= 0 || static_cast<size_t>(len) >= sizeof(date)) return {};
    tp::string identity;
    for (char c : server) {
        switch (c) {
        case '&': identity += "&amp;"; break;
        case '<': identity += "&lt;"; break;
        case '>': identity += "&gt;"; break;
        default: identity += c; break;
        }
    }
    tp::string body = "<html>\r\n<head><title>400 The plain HTTP request was sent to HTTPS port</title></head>\r\n"
                      "<body>\r\n<center><h1>400 Bad Request</h1></center>\r\n"
                      "<center>The plain HTTP request was sent to HTTPS port</center>\r\n";
    if (!identity.empty()) body += "<hr><center>" + identity + "</center>\r\n";
    body += "</body>\r\n</html>\r\n";
    tp::string response = "HTTP/1.1 400 Bad Request\r\n";
    if (!server.empty()) response += "Server: " + server + "\r\n";
    response += "Date: ";
    response += date;
    response += "\r\nContent-Type: text/html\r\nContent-Length: " + tp::to_string(body.size()) +
                "\r\nConnection: close\r\n\r\n";
    return response + body;
}

inline bool is_tls_record_start(const unsigned char* data, size_t length) {
    // Match BoringSSL's initial null-cipher record version and size checks, before it can emit an alert.
    return length == 5 && data[0] == 0x16 && data[1] == 3 &&
           ((static_cast<size_t>(data[3]) << 8) | data[4]) <= 18432;
}

inline bool is_plain_http_start(const unsigned char* data, size_t length) {
    // nginx recognizes HTTP methods from the first five bytes before entering TLS.
    static const char* methods[] = {"GET ", "POST ", "HEAD ", "PUT ", "DELET", "OPTIO", "PATCH", "CONNE", "TRACE"};
    for (const auto* method : methods) {
        const size_t n = std::strlen(method);
        if (length >= n && std::memcmp(data, method, n) == 0) return true;
    }
    return false;
}

#endif
