#include "sources/clamav_source.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <mutex>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace feather {
namespace {

#ifdef _WIN32
using socket_t = SOCKET;
constexpr socket_t kInvalid = INVALID_SOCKET;

std::once_flag g_wsaOnce;
bool g_wsaOk = false;

bool ensureSockets() {
    std::call_once(g_wsaOnce, [] {
        WSADATA data{};
        g_wsaOk = WSAStartup(MAKEWORD(2, 2), &data) == 0;
    });
    return g_wsaOk;
}

void closeSocket(socket_t s) { closesocket(s); }
void setRecvTimeout(socket_t s, int ms) {
    DWORD t = static_cast<DWORD>(ms);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&t),
               sizeof(t));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&t),
               sizeof(t));
}
int lastSocketError() { return WSAGetLastError(); }
#else
using socket_t = int;
constexpr socket_t kInvalid = -1;
bool ensureSockets() { return true; }
void closeSocket(socket_t s) { ::close(s); }
void setRecvTimeout(socket_t s, int ms) {
    timeval tv{};
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}
int lastSocketError() { return errno; }
#endif

struct SocketGuard {
    socket_t handle = kInvalid;
    ~SocketGuard() {
        if (handle != kInvalid) closeSocket(handle);
    }
};

std::string lower(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

std::string trim(std::string s) {
    const char* ws = " \t\r\n\0";
    const std::size_t b = s.find_first_not_of(ws, 0, 5);
    if (b == std::string::npos) return {};
    const std::size_t e = s.find_last_not_of(ws, std::string::npos, 5);
    return s.substr(b, e - b + 1);
}

bool sendAll(socket_t s, const void* data, std::size_t len) {
    const auto* p = static_cast<const char*>(data);
    while (len > 0) {
        const auto sent = ::send(s, p, static_cast<int>(len), 0);
        if (sent <= 0) return false;
        p += sent;
        len -= static_cast<std::size_t>(sent);
    }
    return true;
}

// Reads until a NUL terminator, the buffer fills, or the peer closes.
std::string readReply(socket_t s) {
    std::string out;
    char buf[4096];
    for (;;) {
        const auto got = ::recv(s, buf, sizeof(buf), 0);
        if (got <= 0) break;
        const auto* nul = static_cast<const char*>(std::memchr(buf, '\0', static_cast<std::size_t>(got)));
        if (nul != nullptr) {
            out.append(buf, static_cast<std::size_t>(nul - buf));
            return out;
        }
        out.append(buf, static_cast<std::size_t>(got));
        if (out.size() > 64 * 1024) break;
    }
    return out;
}

} // namespace

Severity classifyClamSignature(const std::string& signature) {
    const std::string s = lower(signature);

    auto startsWith = [&s](const char* prefix) {
        return s.rfind(prefix, 0) == 0;
    };
    auto contains = [&s](const char* needle) {
        return s.find(needle) != std::string::npos;
    };

    // Not evidence of malice, so it must not become a hard verdict.
    if (startsWith("pua.") || startsWith("tool.") || contains("hacktool") ||
        contains(".tool.") || contains("unwanted") || contains("heur")) {
        return Severity::Unwanted;
    }

    return Severity::Malicious;
}

ClamAvSource::ClamAvSource(ClamAvEndpoint endpoint) : endpoint_(std::move(endpoint)) {}

SourceResult ClamAvSource::inspect(const FileFacts& facts) const {
    SourceResult result;

#ifndef _WIN32
    result.error = "clamav source is Windows-only in this build";
    return result;
#else
    if (!ensureSockets()) {
        result.error = "Winsock initialization failed";
        return result;
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    const std::string port = std::to_string(endpoint_.port);
    addrinfo* addresses = nullptr;
    if (getaddrinfo(endpoint_.host.c_str(), port.c_str(), &hints, &addresses) != 0) {
        result.error = "cannot resolve clamd host " + endpoint_.host;
        return result;
    }

    SocketGuard socket;
    for (addrinfo* ai = addresses; ai != nullptr; ai = ai->ai_next) {
        const socket_t candidate =
            ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (candidate == kInvalid) continue;

        setRecvTimeout(candidate, 15000);
        if (::connect(candidate, ai->ai_addr,
                      static_cast<int>(ai->ai_addrlen)) == 0) {
            socket.handle = candidate;
            break;
        }
        closeSocket(candidate);
    }
    freeaddrinfo(addresses);

    if (socket.handle == kInvalid) {
        result.error = "cannot connect to clamd at " + endpoint_.host + ":" +
                       port;
        return result;
    }

    std::ifstream file(facts.path, std::ios::binary);
    if (!file) {
        result.error = "cannot read file for clamd";
        return result;
    }

    // clamd speaks NUL-terminated commands; "z" prefix means NUL-terminated.
    static const char kCommand[] = "zINSTREAM";
    if (!sendAll(socket.handle, kCommand, sizeof(kCommand))) {
        result.error = "failed to send INSTREAM command to clamd";
        return result;
    }

    std::array<char, 64 * 1024> chunk{};
    while (file) {
        file.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
        const std::streamsize got = file.gcount();
        if (got <= 0) break;

        const std::uint32_t length = htonl(static_cast<std::uint32_t>(got));
        if (!sendAll(socket.handle, &length, sizeof(length)) ||
            !sendAll(socket.handle, chunk.data(), static_cast<std::size_t>(got))) {
            result.error = "failed while streaming to clamd";
            return result;
        }
    }

    const std::uint32_t terminator = 0;
    if (!sendAll(socket.handle, &terminator, sizeof(terminator))) {
        result.error = "failed to finish clamd stream";
        return result;
    }

    std::string reply = trim(readReply(socket.handle));
    if (reply.rfind("stream: ", 0) == 0) reply = reply.substr(8);
    reply = trim(reply);

    if (reply.empty()) {
        result.error = "no reply from clamd";
        return result;
    }
    if (reply == "OK") return result;  // clean

    constexpr const char* kFound = " FOUND";
    if (reply.size() > std::strlen(kFound) &&
        reply.compare(reply.size() - std::strlen(kFound), std::strlen(kFound),
                      kFound) == 0) {
        const std::string signature =
            trim(reply.substr(0, reply.size() - std::strlen(kFound)));
        result.signals.push_back(
            Signal{"clamav", "clamav.signature", classifyClamSignature(signature),
                   80, "ClamAV: " + signature});
        return result;
    }

    result.error = "clamd: " + reply;
    return result;
#endif
}

} // namespace feather
