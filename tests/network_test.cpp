// Checks recvmsg over loopback UDP using the Android (bionic) struct layouts the game passes in.
#include "../src/network.h"
#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <cerrno>
#include <chrono>

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
    bool test_recvmsg_stream_no_address() {
        const char *name = "test_recvmsg_stream_no_address";
        int fds[2];
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return fail(name, "socketpair");
        ::write(fds[1], "s", 1);
        char buf[8];
        iovec iov = {buf, sizeof(buf)};
        bionic::sockaddr_in6 from = {};
        bionic_msghdr hdr = {};
        hdr.msg_name = &from;
        hdr.msg_namelen = sizeof(from);
        hdr.msg_iov = &iov;
        hdr.msg_iovlen = 1;
        ssize_t n = -1;
        try {
            n = recv_into(fds[0], hdr);
        } catch (...) {
            ::close(fds[0]); ::close(fds[1]);
            return fail(name, "recvmsg threw");
        }
        ::close(fds[0]); ::close(fds[1]);
        if (n != 1) return fail(name, "wrong byte count");
        if (hdr.msg_namelen != 0) return fail(name, "msg_namelen is not 0 when there is no address");
        return true;
    }

    bool test_recvmsg_small_name_buffer() {
        const char *name = "test_recvmsg_small_name_buffer";
        int rx = shim::socket(bionic::af_family::INET6, bionic::socktype::DGRAM, bionic::ipproto::UDP);
        int off = 0;
        shim::setsockopt(rx, 41, 26, &off, sizeof(off));
        bionic::sockaddr_in6 any6 = {};
        any6.family = (uint16_t) bionic::af_family::INET6;
        shim::bind(rx, &any6, sizeof(any6));
        bionic::sockaddr_in6 bound = {};
        socklen_t len = sizeof(bound);
        shim::getsockname(rx, &bound, &len);
        int tx = shim::socket(bionic::af_family::INET, bionic::socktype::DGRAM, bionic::ipproto::UDP);
        bionic::sockaddr_in to = loopback_any_port();
        to.port = bound.port;
        shim::sendto(tx, "z", 1, 0, &to, sizeof(to));

        char buf[8];
        iovec iov = {buf, sizeof(buf)};
        bionic::sockaddr_in small = {};
        bionic_msghdr hdr = {};
        hdr.msg_name = &small;
        hdr.msg_namelen = sizeof(small);
        hdr.msg_iov = &iov;
        hdr.msg_iovlen = 1;
        ssize_t n = -1;
        try {
            n = recv_into(rx, hdr);
        } catch (...) {
            ::close(rx); ::close(tx);
            return fail(name, "recvmsg threw");
        }
        ::close(rx); ::close(tx);
        if (n != 1) return fail(name, "wrong byte count");
        if (hdr.msg_namelen != sizeof(bionic::sockaddr_in6)) return fail(name, "msg_namelen is not the full address size");
        if (small.family != (uint16_t) bionic::af_family::INET6) return fail(name, "truncated address does not start with family 10");
        return true;
    }
    struct bionic_mmsghdr {
        bionic_msghdr msg_hdr;
        unsigned int msg_len;
    };

    bool test_batch_messages_bionic_layout() {
        const char *name = "test_batch_messages_bionic_layout";
        udp_pair p;
        if (!open_pair(p)) return fail(name, "socket setup");
        char first[] = "alpha", second[] = "beta";
        iovec send_iov[2] = {{first, 5}, {second, 4}};
        bionic_mmsghdr send_headers[2] = {};
        for (int i = 0; i < 2; ++i) {
            send_headers[i].msg_hdr.msg_name = &p.rx_addr;
            send_headers[i].msg_hdr.msg_namelen = sizeof(p.rx_addr);
            send_headers[i].msg_hdr.msg_iov = &send_iov[i];
            send_headers[i].msg_hdr.msg_iovlen = 1;
        }
        int sent = shim::sendmmsg(p.tx, reinterpret_cast<const mmsghdr *>(send_headers), 2, 0);
        char payloads[3][16] = {};
        iovec recv_iov[3];
        bionic::sockaddr_in from[3] = {};
        bionic_mmsghdr received[3] = {};
        for (int i = 0; i < 3; ++i) {
            recv_iov[i] = {payloads[i], sizeof(payloads[i])};
            received[i].msg_hdr.msg_name = &from[i];
            received[i].msg_hdr.msg_namelen = sizeof(from[i]);
            received[i].msg_hdr.msg_iov = &recv_iov[i];
            received[i].msg_hdr.msg_iovlen = 1;
            received[i].msg_hdr.msg_flags = 0x12345678;
            received[i].msg_len = 0xfeed;
        }
        // Wait for both packets: send completion does not guarantee that both
        // datagrams are already observable by a nonblocking receiver.
        timespec deliveryTimeout = {1, 0};
        int count = shim::recvmmsg(p.rx, reinterpret_cast<mmsghdr *>(received), 2, 0, &deliveryTimeout);
        // Android DONTWAIT=0x40 and NOSIGNAL=0x4000 on an empty queue.
        int empty = shim::recvmmsg(p.rx, reinterpret_cast<mmsghdr *>(&received[2]), 1, 0x4040, nullptr);
        int emptyError = errno;
        if (sent != 2 || send_headers[0].msg_len != 5 || send_headers[1].msg_len != 4)
            return fail(name, "send batch stride or lengths");
        if (count != 2 || received[0].msg_len != 5 || received[1].msg_len != 4 || received[2].msg_len != 0xfeed) {
            fprintf(stderr, "batch receive count=%d lengths=%u,%u,%u errno=%d headerSize=%zu batchSize=%zu\n",
                    count, received[0].msg_len, received[1].msg_len, received[2].msg_len, errno,
                    sizeof(bionic_msghdr), sizeof(bionic_mmsghdr));
            close_pair(p);
            return fail(name, "receive stride or lengths");
        }
        if (memcmp(payloads[0], "alpha", 5) || memcmp(payloads[1], "beta", 4))
            return fail(name, "batch payloads");
        for (int i = 0; i < 2; ++i) {
            if (from[i].family != (uint16_t)bionic::af_family::INET || from[i].port != p.tx_addr.port)
                return fail(name, "translated sender address");
            if (received[i].msg_hdr.msg_flags != 0 || received[i].msg_hdr.msg_controllen != 0 ||
                received[i].msg_hdr.msg_name != &from[i])
                return fail(name, "translated header output");
        }
        if (empty != -1 || (emptyError != EAGAIN && emptyError != EWOULDBLOCK)) {
            close_pair(p);
            return fail(name, "empty nonblocking batch");
        }
        send_bytes(p, "partial", 7);
        timespec partialTimeout = {0, 50000000};
        int partial = shim::recvmmsg(p.rx, reinterpret_cast<mmsghdr *>(received), 3, 0, &partialTimeout);
        close_pair(p);
        if (partial != 1 || received[0].msg_len != 7 || received[1].msg_len != 4 || received[2].msg_len != 0xfeed)
            return fail(name, "partial batch timeout or untouched trailing lengths");
        return true;
    }

    bool test_recvmmsg_initial_timeout() {
        const char *name = "test_recvmmsg_initial_timeout";
        udp_pair p;
        if (!open_pair(p)) return fail(name, "socket setup");
        char payload[8];
        iovec iov = {payload, sizeof(payload)};
        bionic_mmsghdr header = {};
        header.msg_hdr.msg_iov = &iov;
        header.msg_hdr.msg_iovlen = 1;
        timespec timeout = {0, 0};
        int count = shim::recvmmsg(p.rx, reinterpret_cast<mmsghdr *>(&header), 1, 0, &timeout);
        close_pair(p);
        return count == 0 || fail(name, "empty batch did not time out before first receive");
    }

}

int main() {
    bool (*tests[])() = {
        test_recvmsg_fills_caller_address,
        test_recvmsg_keeps_msg_name,
        test_recvmsg_reused_header,
        test_recvmsg_reports_trunc,
        test_recvmsg_v4_mapped,
        test_recvmsg_stream_no_address,
        test_recvmsg_small_name_buffer,
        test_batch_messages_bionic_layout,
        test_recvmmsg_initial_timeout,
    };
    int failed = 0;
    for (auto t : tests)
        if (!t()) failed++;
    printf("%d of %zu tests passed\n", (int) (sizeof(tests) / sizeof(tests[0])) - failed, sizeof(tests) / sizeof(tests[0]));
    return failed ? 1 : 0;
}
