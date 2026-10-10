// Checks recvmsg over loopback UDP using the Android (bionic) struct layouts the game passes in.
#include "../src/network.h"
#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <sys/uio.h>
#include <unistd.h>

using namespace shim;

namespace {
    // 64-bit Android msghdr. msg_iovlen and msg_controllen are size_t here, unlike macOS.
    struct bionic_msghdr {
        void *msg_name;
        socklen_t msg_namelen;
        struct iovec *msg_iov;
        size_t msg_iovlen;
        void *msg_control;
        size_t msg_controllen;
        int msg_flags;
    };

    constexpr int BIONIC_MSG_TRUNC = 0x20;

    struct udp_pair {
        int rx = -1;
        int tx = -1;
        bionic::sockaddr_in rx_addr = {};
        bionic::sockaddr_in tx_addr = {};
    };

    bool fail(const char *test, const char *what) {
        fprintf(stderr, "FAIL %s: %s\n", test, what);
        return false;
    }

    bionic::sockaddr_in loopback_any_port() {
        bionic::sockaddr_in a = {};
        a.family = (uint16_t) bionic::af_family::INET;
        a.port = 0;
        a.addr = htonl(INADDR_LOOPBACK);
        return a;
    }

    bool open_pair(udp_pair &p) {
        p.rx = shim::socket(bionic::af_family::INET, bionic::socktype::DGRAM, bionic::ipproto::UDP);
        p.tx = shim::socket(bionic::af_family::INET, bionic::socktype::DGRAM, bionic::ipproto::UDP);
        if (p.rx < 0 || p.tx < 0)
            return false;
        auto any = loopback_any_port();
        if (shim::bind(p.rx, &any, sizeof(any)) != 0 || shim::bind(p.tx, &any, sizeof(any)) != 0)
            return false;
        socklen_t len = sizeof(p.rx_addr);
        shim::getsockname(p.rx, &p.rx_addr, &len);
        len = sizeof(p.tx_addr);
        shim::getsockname(p.tx, &p.tx_addr, &len);
        return true;
    }

    void close_pair(udp_pair &p) {
        ::close(p.rx);
        ::close(p.tx);
    }

    bool send_bytes(udp_pair &p, const char *data, size_t len) {
        return shim::sendto(p.tx, data, len, 0, &p.rx_addr, sizeof(p.rx_addr)) == (ssize_t) len;
    }

    ssize_t recv_into(int fd, bionic_msghdr &hdr) {
        return shim::recvmsg(fd, (struct msghdr *) &hdr, 0);
    }

    bool test_recvmsg_fills_caller_address() {
        const char *name = "test_recvmsg_fills_caller_address";
        udp_pair p;
        if (!open_pair(p)) return fail(name, "socket setup");
        send_bytes(p, "hello", 5);
        char buf[16];
        iovec iov = {buf, sizeof(buf)};
        bionic::sockaddr_in from = {};
        bionic_msghdr hdr = {};
        hdr.msg_name = &from;
        hdr.msg_namelen = sizeof(from);
        hdr.msg_iov = &iov;
        hdr.msg_iovlen = 1;
        ssize_t n = recv_into(p.rx, hdr);
        close_pair(p);
        if (n != 5) return fail(name, "wrong byte count");
        if (from.family != (uint16_t) bionic::af_family::INET) return fail(name, "family is not 2");
        if (from.port != p.tx_addr.port) return fail(name, "port does not match sender");
        if (from.addr != htonl(INADDR_LOOPBACK)) return fail(name, "address is not 127.0.0.1");
        return true;
    }

    bool test_recvmsg_keeps_msg_name() {
        const char *name = "test_recvmsg_keeps_msg_name";
        udp_pair p;
        if (!open_pair(p)) return fail(name, "socket setup");
        send_bytes(p, "x", 1);
        char buf[16];
        iovec iov = {buf, sizeof(buf)};
        bionic::sockaddr_in from = {};
        bionic_msghdr hdr = {};
        hdr.msg_name = &from;
        hdr.msg_namelen = sizeof(from);
        hdr.msg_iov = &iov;
        hdr.msg_iovlen = 1;
        recv_into(p.rx, hdr);
        close_pair(p);
        if (hdr.msg_name != &from) return fail(name, "msg_name points somewhere else after the call");
        return true;
    }

    bool test_recvmsg_reused_header() {
        const char *name = "test_recvmsg_reused_header";
        udp_pair p;
        if (!open_pair(p)) return fail(name, "socket setup");
        char buf[16];
        iovec iov = {buf, sizeof(buf)};
        bionic::sockaddr_in from = {};
        bionic_msghdr hdr = {};
        hdr.msg_name = &from;
        hdr.msg_namelen = sizeof(from);
        hdr.msg_iov = &iov;
        hdr.msg_iovlen = 1;
        for (int i = 0; i < 3; i++) {
            send_bytes(p, "abc", 3);
            from = {};
            if (recv_into(p.rx, hdr) != 3) { close_pair(p); return fail(name, "wrong byte count"); }
            if (from.port != p.tx_addr.port) { close_pair(p); return fail(name, "caller address not filled on a later call"); }
        }
        close_pair(p);
        return true;
    }

    bool test_recvmsg_reports_trunc() {
        const char *name = "test_recvmsg_reports_trunc";
        udp_pair p;
        if (!open_pair(p)) return fail(name, "socket setup");
        char big[64];
        memset(big, 'a', sizeof(big));
        send_bytes(p, big, sizeof(big));
        char buf[8];
        iovec iov = {buf, sizeof(buf)};
        bionic_msghdr hdr = {};
        hdr.msg_iov = &iov;
        hdr.msg_iovlen = 1;
        ssize_t n = recv_into(p.rx, hdr);
        close_pair(p);
        if (n < 0) return fail(name, "recvmsg failed");
        if (!(hdr.msg_flags & BIONIC_MSG_TRUNC)) return fail(name, "MSG_TRUNC (0x20) not set");
        return true;
    }

    bool test_recvmsg_v4_mapped() {
        const char *name = "test_recvmsg_v4_mapped";
        int rx = shim::socket(bionic::af_family::INET6, bionic::socktype::DGRAM, bionic::ipproto::UDP);
        int off = 0;
        shim::setsockopt(rx, 41, 26, &off, sizeof(off));
        bionic::sockaddr_in6 any6 = {};
        any6.family = (uint16_t) bionic::af_family::INET6;
        if (shim::bind(rx, &any6, sizeof(any6)) != 0) return fail(name, "bind ::");
        bionic::sockaddr_in6 bound = {};
        socklen_t len = sizeof(bound);
        shim::getsockname(rx, &bound, &len);

        int tx = shim::socket(bionic::af_family::INET, bionic::socktype::DGRAM, bionic::ipproto::UDP);
        bionic::sockaddr_in to = loopback_any_port();
        to.port = bound.port;
        shim::sendto(tx, "v4", 2, 0, &to, sizeof(to));

        char buf[16];
        iovec iov = {buf, sizeof(buf)};
        bionic::sockaddr_in6 from = {};
        bionic_msghdr hdr = {};
        hdr.msg_name = &from;
        hdr.msg_namelen = sizeof(from);
        hdr.msg_iov = &iov;
        hdr.msg_iovlen = 1;
        ssize_t n = recv_into(rx, hdr);
        ::close(rx);
        ::close(tx);
        if (n != 2) return fail(name, "wrong byte count");
        if (from.family != (uint16_t) bionic::af_family::INET6) return fail(name, "family is not 10");
        static const uint8_t mapped[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1};
        if (memcmp(from.addr, mapped, 16) != 0) return fail(name, "address is not ::ffff:127.0.0.1");
        return true;
    }
}

int main() {
    bool (*tests[])() = {
        test_recvmsg_fills_caller_address,
        test_recvmsg_keeps_msg_name,
        test_recvmsg_reused_header,
        test_recvmsg_reports_trunc,
        test_recvmsg_v4_mapped,
    };
    int failed = 0;
    for (auto t : tests)
        if (!t()) failed++;
    printf("%d of %zu tests passed\n", (int) (sizeof(tests) / sizeof(tests[0])) - failed, sizeof(tests) / sizeof(tests[0]));
    return failed ? 1 : 0;
}
