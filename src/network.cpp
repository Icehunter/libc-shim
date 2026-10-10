#include "no-fortify.h"
#include "network.h"
#include "errno.h"

#ifdef __FreeBSD__
// They're under #ifdef _KERNEL.
// I moved them into here to prevent other errors that can occur
// because _KERNEL isn't intended for general purpose usage.
// Taken from netinet6/in6.h and removed comments.
#define IPV6_2292PKTINFO	19
#define IPV6_2292HOPLIMIT	20
#define IPV6_2292NEXTHOP	21
#define IPV6_2292HOPOPTS	22
#define IPV6_2292DSTOPTS	23
#define IPV6_2292RTHDR		24
#define IPV6_2292PKTOPTIONS	25
#endif

#include <netinet/in.h>
#ifdef __FreeBSD__
#undef _KERNEL
#endif
#include <sys/un.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <cstring>
#include <ifaddrs.h>

namespace {
    bool netdbg() {
        static bool on = getenv("SHIM_NETDBG") != nullptr;
        return on;
    }

    void netdbg_log(const char *fn, int fd, const ::sockaddr *sa, ssize_t ret, size_t len, int extra) {
        if (!netdbg()) return;
        char host[INET6_ADDRSTRLEN] = "-";
        int port = 0;
        if (sa && sa->sa_family == AF_INET) {
            auto in = (const ::sockaddr_in *) sa;
            inet_ntop(AF_INET, &in->sin_addr, host, sizeof(host));
            port = ntohs(in->sin_port);
        } else if (sa && sa->sa_family == AF_INET6) {
            auto in6 = (const ::sockaddr_in6 *) sa;
            inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof(host));
            port = ntohs(in6->sin6_port);
        }
        fprintf(stderr, "NETDBG %s fd=%d peer=%s:%d len=%zu ret=%zd errno=%d extra=%d\n", fn, fd, host, port, len, ret, ret < 0 ? errno : 0, extra);
    }

}

using namespace shim;

bionic::ai_flags bionic::from_host_ai_flags(int flags) {
    uint32_t ret = 0;
    if (flags & AI_PASSIVE)
        ret |= (uint32_t) ai_flags::PASSIVE;
    if (flags & AI_CANONNAME)
        ret |= (uint32_t) ai_flags::CANONNAME;
    if (flags & AI_NUMERICHOST)
        ret |= (uint32_t) ai_flags::NUMERICHOST;
    return (bionic::ai_flags) ret;
}

int bionic::to_host_ai_flags(bionic::ai_flags flags) {
    int ret = 0;
    if ((uint32_t) flags & (uint32_t) ai_flags::PASSIVE)
        ret |= AI_PASSIVE;
    if ((uint32_t) flags & (uint32_t) ai_flags::CANONNAME)
        ret |= AI_CANONNAME;
    if ((uint32_t) flags & (uint32_t) ai_flags::NUMERICHOST)
        ret |= AI_NUMERICHOST;
    return ret;
}

bionic::af_family bionic::from_host_af_family(int family) {
    switch (family) {
        case AF_UNSPEC: return af_family::UNSPEC;
        case AF_UNIX: return af_family::UNIX;
        case AF_INET: return af_family::INET;
        case AF_INET6: return af_family::INET6;
#ifdef AF_NETLINK
        case AF_NETLINK: return af_family::NETLINK;
#endif
        default: return af_family::UNSPEC;
    }
}

int bionic::to_host_af_family(bionic::af_family family) {
    switch (family) {
        case af_family::UNSPEC: return AF_UNSPEC;
        case af_family::UNIX: return AF_UNIX;
        case af_family::INET: return AF_INET;
        case af_family::INET6: return AF_INET6;
#ifdef AF_NETLINK
        case af_family::NETLINK: return AF_NETLINK;
#endif
        default: return AF_UNSPEC;
    }
}

bionic::socktype bionic::from_host_socktype(int socktype) {
    switch (socktype) {
        case SOCK_STREAM: return socktype::STREAM;
        case SOCK_DGRAM: return socktype::DGRAM;
        case SOCK_RAW: return socktype::RAW;
        default: handle_runtime_error("Unknown socktype %d", socktype);
    }
}

int bionic::to_host_socktype(bionic::socktype socktype) {
    switch ((bionic::socktype)((intptr_t)socktype & 0b11)) {
        case socktype::STREAM: return SOCK_STREAM;
        case socktype::DGRAM: return SOCK_DGRAM;
        case socktype::RAW: return SOCK_RAW;
        default: handle_runtime_error("Unknown socktype %d", (int)socktype);
    }
}

bionic::ipproto bionic::from_host_ipproto(int proto) {
    switch (proto) {
        case IPPROTO_IP: return ipproto::IP;
        case IPPROTO_TCP: return ipproto::TCP;
        case IPPROTO_UDP: return ipproto::UDP;
        case IPPROTO_IPV6: return ipproto::IPV6;
        default: handle_runtime_error("Unknown ipproto %d", proto);
    }
}

int bionic::to_host_ipproto(bionic::ipproto proto) {
    switch (proto) {
        case ipproto::IP: return IPPROTO_IP;
        case ipproto::TCP: return IPPROTO_TCP;
        case ipproto::UDP: return IPPROTO_UDP;
        case ipproto::IPV6: return IPPROTO_IPV6;
        default: handle_runtime_error("Unknown ipproto %d", (int)proto);
    }
}

void bionic::from_host(const ::sockaddr *in, bionic::sockaddr *out) {
    switch (in->sa_family) {
        case AF_UNSPEC:
            out->family = (uint16_t) af_family::UNSPEC;
            break;
        case AF_UNIX:
            ((bionic::sockaddr_un *)out)->family = ((::sockaddr_un *)in)->sun_family;
            memcpy(((bionic::sockaddr_un *)out)->sun_path, ((::sockaddr_un *)in)->sun_path, 108);
            break;    
        case AF_INET:
            out->family = (uint16_t) af_family::INET;
            ((bionic::sockaddr_in *) out)->port = ((::sockaddr_in*) in)->sin_port;
            ((bionic::sockaddr_in *) out)->addr = ((::sockaddr_in*) in)->sin_addr.s_addr;
            break;
        case AF_INET6:
            out->family = (uint16_t) af_family::INET6;
            ((bionic::sockaddr_in6 *) out)->port = ((::sockaddr_in6*) in)->sin6_port;
            ((bionic::sockaddr_in6 *) out)->flow_info = ((::sockaddr_in6*) in)->sin6_flowinfo;
            memcpy(((bionic::sockaddr_in6 *) out)->addr, ((::sockaddr_in6*) in)->sin6_addr.s6_addr, 16);
            ((bionic::sockaddr_in6 *) out)->scope = ((::sockaddr_in6*) in)->sin6_scope_id;
            break;
        default: handle_runtime_error("Unknown socket family when converting sockaddr from host %d", (int)in->sa_family);
    }
}

void bionic::to_host(const bionic::sockaddr *in, ::sockaddr *out) {
    switch ((af_family) in->family) {
        case af_family::UNSPEC:
            out->sa_family = AF_UNSPEC;
            break;
        case af_family::UNIX:
            ((::sockaddr_un *)out)->sun_family = ((bionic::sockaddr_un *)in)->family;
            memcpy(((::sockaddr_un *)out)->sun_path, ((bionic::sockaddr_un *)in)->sun_path, 108);
            break;
        case af_family::INET:
            out->sa_family = AF_INET;
            ((::sockaddr_in*) out)->sin_port = ((bionic::sockaddr_in *) in)->port;
            ((::sockaddr_in*) out)->sin_addr.s_addr = ((bionic::sockaddr_in *) in)->addr;
            break;
        case af_family::INET6:
            out->sa_family = AF_INET6;
            ((::sockaddr_in6*) out)->sin6_port = ((bionic::sockaddr_in6 *) in)->port;
            ((::sockaddr_in6*) out)->sin6_flowinfo = ((bionic::sockaddr_in6 *) in)->flow_info;
            memcpy(((::sockaddr_in6*) out)->sin6_addr.s6_addr, ((bionic::sockaddr_in6 *) in)->addr, 16);
            ((::sockaddr_in6*) out)->sin6_scope_id = ((bionic::sockaddr_in6 *) in)->scope;
            break;
        default: handle_runtime_error("Unknown socket family when converting sockaddr to host %d", (int)in->family);
    }
}

size_t bionic::get_host_len(const bionic::sockaddr *in) {
    if (!in)
        return 0;
    switch ((af_family) in->family) {
        case af_family::UNIX: return sizeof(::sockaddr_un);
        case af_family::INET: return sizeof(::sockaddr_in);
        case af_family::INET6: return sizeof(::sockaddr_in6);
        default: handle_runtime_error("Unknown socket family when converting sockaddr to host %d", (int)in->family);
    }
}

size_t bionic::get_bionic_len(const ::sockaddr *in) {
    if (!in)
        return 0;
    switch (in->sa_family) {
        case AF_UNIX: return sizeof(bionic::sockaddr_un);
        case AF_INET: return sizeof(bionic::sockaddr_in);
        case AF_INET6: return sizeof(bionic::sockaddr_in6);
        default: handle_runtime_error("Unknown socket family when converting sockaddr from host %d", (int)in->sa_family);
    }
}

bionic::addrinfo* bionic::from_host_alloc(const ::addrinfo *in) {
    if (!in)
        return nullptr;

    auto out = new addrinfo;
    try {
        out->ai_flags = from_host_ai_flags(in->ai_flags);
        out->ai_family = from_host_af_family(in->ai_family);
        out->ai_socktype = from_host_socktype(in->ai_socktype);
        out->ai_protocol = from_host_ipproto(in->ai_protocol);
        out->ai_addrlen = get_bionic_len(in->ai_addr);
        out->ai_addr = nullptr;
        if (out->ai_addrlen) {
            out->ai_addr = (bionic::sockaddr *) malloc(out->ai_addrlen);
            from_host(in->ai_addr, out->ai_addr);
        }
        out->ai_canonname = in->ai_canonname ? strdup(in->ai_canonname) : nullptr;

        out->ai_next = from_host_alloc(in->ai_next);
        return out;
    }
    catch (std::exception& ex) {
        ::fprintf(::stderr, "libc-shim from_host_alloc(addrinfo) runtime error: %s", ex.what());
        ::fflush(::stderr);

        delete out;
        //TODO Log errors
        return from_host_alloc(in->ai_next);
    }
}

void bionic::free_bionic_list(bionic::addrinfo *list) {
    while (list) {
        free(list->ai_addr);
        free(list->ai_canonname);
        auto tmp = list;
        list = list->ai_next;
        delete tmp;
    }
}

::addrinfo* bionic::to_host_alloc(const bionic::addrinfo *in) {
    if (!in)
        return nullptr;

    auto out = new ::addrinfo;
    out->ai_flags = to_host_ai_flags(in->ai_flags);
    out->ai_family = to_host_af_family(in->ai_family);
    // ai_socktype == 0 is only allowed here, see man getaddrinfo
    out->ai_socktype = in->ai_socktype != (bionic::socktype)0 ? to_host_socktype(in->ai_socktype) : 0;
    out->ai_protocol = to_host_ipproto(in->ai_protocol);
    out->ai_addrlen = get_host_len(in->ai_addr);
    out->ai_addr = nullptr;
    if (out->ai_addrlen) {
        out->ai_addr = (::sockaddr *) malloc(out->ai_addrlen);
        to_host(in->ai_addr, out->ai_addr);
    }
    out->ai_canonname = in->ai_canonname;

    out->ai_next = to_host_alloc(in->ai_next);
    return out;
}

void bionic::free_host_list(::addrinfo *list) {
    while (list) {
        free(list->ai_addr);
        auto tmp = list;
        list = list->ai_next;
        delete tmp;
    }
}

int bionic::to_host_nameinfo_flags(bionic::nameinfo_flags flags) {
    int ret = 0;
    if ((uint32_t) flags & (uint32_t) nameinfo_flags::NOFQDN)
        ret |= NI_NOFQDN;
    if ((uint32_t) flags & (uint32_t) nameinfo_flags::NUMERICHOST)
        ret |= NI_NUMERICHOST;
    if ((uint32_t) flags & (uint32_t) nameinfo_flags::NAMEREQD)
        ret |= NI_NAMEREQD;
    if ((uint32_t) flags & (uint32_t) nameinfo_flags::NUMERICSERV)
        ret |= NI_NUMERICSERV;
    if ((uint32_t) flags & (uint32_t) nameinfo_flags::DGRAM)
        ret |= NI_DGRAM;
    return ret;
}

int bionic::to_host_sockopt_so(int opt) {
    switch (opt) {
        case 1: return SO_DEBUG;
        case 2: return SO_REUSEADDR;
        case 3: return SO_TYPE;
        case 4: return SO_ERROR;
        case 5: return SO_DONTROUTE;
        case 6: return SO_BROADCAST;
        case 7: return SO_SNDBUF;
        case 8: return SO_RCVBUF;
        case 9: return SO_KEEPALIVE;
        case 10: return SO_OOBINLINE;
        case 13: return SO_LINGER;
        case 15: return SO_REUSEPORT;
#ifdef SO_TIMESTAMP_OLD
        case 29: return SO_TIMESTAMP_OLD;
#else
        case 29: return SO_TIMESTAMP;
#endif
#ifdef SO_TIMESTAMP_NEW
        case 63: return SO_TIMESTAMP_NEW;
#endif
        default: handle_runtime_error("Unknown SO sockopt %d", opt);
    }
}

int bionic::to_host_sockopt_ip(int opt) {
    switch (opt) {
        case 1: return IP_TOS;
        case 2: return IP_TTL;
        case 3: return IP_HDRINCL;
        case 4: return IP_OPTIONS;
        case 6: return IP_RECVOPTS;
        case 7: return IP_RETOPTS;
        case 16: return IP_IPSEC_POLICY;
        case 32: return IP_MULTICAST_IF;
        case 33: return IP_MULTICAST_TTL;
        case 34: return IP_MULTICAST_LOOP;
        case 35: return IP_ADD_MEMBERSHIP;
        case 36: return IP_DROP_MEMBERSHIP;
        default: handle_runtime_error("Unknown IP sockopt %d", opt);
    }
}

int bionic::to_host_sockopt_ipv6(int opt) {
    switch (opt) {
        case 2: return IPV6_2292PKTINFO;
        case 3: return IPV6_2292HOPOPTS;
        case 4: return IPV6_2292DSTOPTS;
        case 5: return IPV6_2292RTHDR;
        case 6: return IPV6_2292PKTOPTIONS;
        case 7: return IPV6_CHECKSUM;
        case 8: return IPV6_2292HOPLIMIT;
        case 16: return IPV6_UNICAST_HOPS;
        case 17: return IPV6_MULTICAST_IF;
        case 18: return IPV6_MULTICAST_HOPS;
        case 19: return IPV6_MULTICAST_LOOP;
        case 20: return IPV6_JOIN_GROUP;
        case 21: return IPV6_LEAVE_GROUP;
        case 26: return IPV6_V6ONLY;
        case 34: return IPV6_IPSEC_POLICY;
        default: handle_runtime_error("Unknown IPv6 sockopt %d", opt);
    }
}

int bionic::to_host_sockopt_level(int level) {
    if (level == 1) return SOL_SOCKET;
    return to_host_ipproto((ipproto) level);
}

int bionic::to_host_sockopt(int level, int opt) {
    level = to_host_sockopt_level(level);
    switch (level) {
        case SOL_SOCKET: return to_host_sockopt_so(opt);
        case IPPROTO_IP: return to_host_sockopt_ip(opt);
        case IPPROTO_IPV6: return to_host_sockopt_ipv6(opt);
        case IPPROTO_TCP: return opt;
        default: handle_runtime_error("Unknown sockopt level %d", level);
    }
}

int shim::socket(bionic::af_family domain, bionic::socktype type, bionic::ipproto proto) {
    int ret = ::socket(bionic::to_host_af_family(domain), bionic::to_host_socktype(type), bionic::to_host_ipproto(proto));
    if (netdbg()) fprintf(stderr, "NETDBG socket domain=%d type=%d proto=%d ret=%d errno=%d\n", (int) domain, (int) type, (int) proto, ret, ret < 0 ? errno : 0);
    return ret;
}

int shim::getaddrinfo(const char *node, const char *service, const bionic::addrinfo *hints, bionic::addrinfo **res) {
    auto hhints = bionic::to_host_alloc(hints);
    ::addrinfo *hres;
    int ret = ::getaddrinfo(node, service, hhints, &hres);
    bionic::free_host_list(hhints);
    if (ret != 0)
        return ret;
    *res = bionic::from_host_alloc(hres);
    freeaddrinfo(hres);
    return 0;
}

void shim::freeaddrinfo(bionic::addrinfo *ai) {
    bionic::free_bionic_list(ai);
}

enum class IFF : unsigned int {
  UP = 1 << 0,
  BROADCAST = 1 << 1,
  DEBUG = 1 << 2,
  LOOPBACK = 1 << 3,
  POINTOPOINT = 1 << 4,
  NOTRAILERS = 1 << 5,
  RUNNING = 1 << 6,
  NOARP = 1 << 7,
  PROMISC = 1 << 8,
  ALLMULTI = 1 << 9,
  MASTER = 1 << 10,
  SLAVE = 1 << 11,
  MULTICAST = 1 << 12,
  PORTSEL = 1 << 13,
  AUTOMEDIA = 1 << 14,
  DYNAMIC = 1 << 15,
  LOWER_UP = 1 << 16,
  DORMANT = 1 << 17,
  ECHO = 1 << 18,
};

int shim::getifaddrs(bionic::ifaddrs** result) {
    ::ifaddrs * nresult = nullptr;
    auto ret = ::getifaddrs(&nresult);
    if(ret != 0) {
        return ret;
    }
    bionic::ifaddrs* pc = nullptr;
    auto c = nresult;
    *result = nullptr;
    while(c) {
        auto v4 = c->ifa_addr && c->ifa_addr->sa_family == AF_INET;
        auto v6 = c->ifa_addr && c->ifa_addr->sa_family == AF_INET6;
        if(v4 || v6) {
            shim::bionic::ifaddrs * n = new bionic::ifaddrs;
            n->ifa_addr = (bionic::sockaddr*)malloc(bionic::get_bionic_len(c->ifa_addr));
            bionic::from_host(c->ifa_addr, n->ifa_addr);
            if(c->ifa_netmask && (c->ifa_netmask->sa_family == AF_INET || c->ifa_netmask->sa_family == AF_INET6)) {
                auto len = bionic::get_bionic_len(c->ifa_netmask);
                n->ifa_netmask = (bionic::sockaddr*)malloc(len);
                bionic::from_host(c->ifa_netmask, n->ifa_netmask);
            } else {
                n->ifa_netmask = nullptr;
            }
            n->ifa_name = c->ifa_name ? strdup(c->ifa_name) : nullptr;
            n->ifa_flags = 0;
            // #ifdef IFF_$0
            // if(c->ifa_flags & IFF_$0) {
            //     n->ifa_flags |= (unsigned int)IFF::$0;
            // }
            // #endif
            #ifdef IFF_UP
            if(c->ifa_flags & IFF_UP) {
                n->ifa_flags |= (unsigned int)IFF::UP;
            }
            #endif
            #ifdef IFF_BROADCAST
            if(c->ifa_flags & IFF_BROADCAST) {
                n->ifa_flags |= (unsigned int)IFF::BROADCAST;
            }
            #endif
            #ifdef IFF_DEBUG
            if(c->ifa_flags & IFF_DEBUG) {
                n->ifa_flags |= (unsigned int)IFF::DEBUG;
            }
            #endif
            #ifdef IFF_LOOPBACK
            if(c->ifa_flags & IFF_LOOPBACK) {
                n->ifa_flags |= (unsigned int)IFF::LOOPBACK;
            }
            #endif
            #ifdef IFF_POINTOPOINT
            if(c->ifa_flags & IFF_POINTOPOINT) {
                n->ifa_flags |= (unsigned int)IFF::POINTOPOINT;
            }
            #endif
            #ifdef IFF_NOTRAILERS
            if(c->ifa_flags & IFF_NOTRAILERS) {
                n->ifa_flags |= (unsigned int)IFF::NOTRAILERS;
            }
            #endif
            #ifdef IFF_RUNNING
            if(c->ifa_flags & IFF_RUNNING) {
                n->ifa_flags |= (unsigned int)IFF::RUNNING;
            }
            #endif
            #ifdef IFF_NOARP
            if(c->ifa_flags & IFF_NOARP) {
                n->ifa_flags |= (unsigned int)IFF::NOARP;
            }
            #endif
            #ifdef IFF_PROMISC
            if(c->ifa_flags & IFF_PROMISC) {
                n->ifa_flags |= (unsigned int)IFF::PROMISC;
            }
            #endif
            #ifdef IFF_ALLMULTI
            if(c->ifa_flags & IFF_ALLMULTI) {
                n->ifa_flags |= (unsigned int)IFF::ALLMULTI;
            }
            #endif
            #ifdef IFF_MASTER
            if(c->ifa_flags & IFF_MASTER) {
                n->ifa_flags |= (unsigned int)IFF::MASTER;
            }
            #endif
            #ifdef IFF_SLAVE
            if(c->ifa_flags & IFF_SLAVE) {
                n->ifa_flags |= (unsigned int)IFF::SLAVE;
            }
            #endif
            #ifdef IFF_MULTICAST
            if(c->ifa_flags & IFF_MULTICAST) {
                n->ifa_flags |= (unsigned int)IFF::MULTICAST;
            }
            #endif
            #ifdef IFF_PORTSEL
            if(c->ifa_flags & IFF_PORTSEL) {
                n->ifa_flags |= (unsigned int)IFF::PORTSEL;
            }
            #endif
            #ifdef IFF_AUTOMEDIA
            if(c->ifa_flags & IFF_AUTOMEDIA) {
                n->ifa_flags |= (unsigned int)IFF::AUTOMEDIA;
            }
            #endif
            #ifdef IFF_DYNAMIC
            if(c->ifa_flags & IFF_DYNAMIC) {
                n->ifa_flags |= (unsigned int)IFF::DYNAMIC;
            }
            #endif
            #ifdef IFF_LOWER_UP
            if(c->ifa_flags & IFF_LOWER_UP) {
                n->ifa_flags |= (unsigned int)IFF::LOWER_UP;
            }
            #endif
            #ifdef IFF_DORMANT
            if(c->ifa_flags & IFF_DORMANT) {
                n->ifa_flags |= (unsigned int)IFF::DORMANT;
            }
            #endif
            #ifdef IFF_ECHO
            if(c->ifa_flags & IFF_ECHO) {
                n->ifa_flags |= (unsigned int)IFF::ECHO;
            }
            #endif
            n->ifa_next = nullptr;
            if(pc == nullptr) {
                *result = n;
            } else {
                pc->ifa_next = n;
            }
            pc = n;
        }
        c = c->ifa_next;
    }
    ::freeifaddrs(nresult);
    return 0;
}

void shim::freeifaddrs(shim::bionic::ifaddrs *c) {
    while(c) {
        if(c->ifa_addr) {
            free(c->ifa_addr);
        }
        if(c->ifa_netmask) {
            free(c->ifa_netmask);
        }
        if(c->ifa_name) {
            free(c->ifa_name);
        }
        auto n = c->ifa_next;
        delete c;
        c = n;
    }
}

int shim::getnameinfo(const bionic::sockaddr *addr, socklen_t addrlen, char *host, socklen_t hostlen,
        char *serv, socklen_t servlen, bionic::nameinfo_flags flags) {
    try {
        detail::sockaddr_in haddr (addr, addrlen);
        return ::getnameinfo(haddr.ptr(), haddr.len, host, hostlen, serv, servlen,
                bionic::to_host_nameinfo_flags(flags));
    } catch  (std::exception& ex) {
        ::fprintf(::stderr, "libc-shim getnameinfo runtime error: %s", ex.what());
        ::fflush(::stderr);

        // TODO: A random sockaddr is passed to this function,
        // while connecting to Minecraft win10
        return 5 /* EAI_FAMILY */;
    }
}

int shim::bind(int sockfd, const bionic::sockaddr *addr, socklen_t addrlen) {
    detail::sockaddr_in haddr (addr, addrlen);
    int ret = ::bind(sockfd, haddr.ptr(), haddr.len);
    netdbg_log("bind", sockfd, haddr.ptr(), ret, haddr.len, 0);
    return ret;
}

int shim::connect(int sockfd, const bionic::sockaddr *addr, socklen_t addrlen) {
    detail::sockaddr_in haddr (addr, addrlen);
    int ret = ::connect(sockfd, haddr.ptr(), haddr.len);
    netdbg_log("connect", sockfd, haddr.ptr(), ret, haddr.len, 0);
    return ret;
}

ssize_t shim::send(int sockfd, const void *buf, size_t len, int flags) {
    detail::sock_send_flags hflags (sockfd, flags);
    auto ret = ::send(sockfd, buf, len, hflags.flags);
    netdbg_log("send", sockfd, nullptr, ret, len, flags);
    return ret;
}

namespace {
    // struct msghdr as laid out by bionic on 64-bit Android. iovec matches the host layout.
    struct bionic_msghdr {
        void *msg_name;
        socklen_t msg_namelen;
        struct iovec *msg_iov;
        size_t msg_iovlen;
        void *msg_control;
        size_t msg_controllen;
        int msg_flags;
    };

    constexpr int BIONIC_MSG_CTRUNC = 0x8;
    constexpr int BIONIC_MSG_TRUNC = 0x20;

    int to_host_recv_flags(int flags) {
        int ret = 0;
        if (flags & 0x2) ret |= MSG_PEEK;
        if (flags & BIONIC_MSG_TRUNC) ret |= MSG_TRUNC;
        if (flags & 0x40) ret |= MSG_DONTWAIT;
        if (flags & 0x100) ret |= MSG_WAITALL;
        int known = 0x2 | BIONIC_MSG_TRUNC | 0x40 | 0x100 | 0x4000;
        if (flags & ~known)
            handle_runtime_error("recvmsg with unsupported flags %d", flags);
        return ret;
    }

    int from_host_msg_flags(int flags) {
        int ret = 0;
        if (flags & MSG_TRUNC) ret |= BIONIC_MSG_TRUNC;
        if (flags & MSG_CTRUNC) ret |= BIONIC_MSG_CTRUNC;
        return ret;
    }


    void warn_control_once(const char *fn) {
        static bool warned = false;
        if (!warned) {
            warned = true;
            fprintf(stderr, "libc-shim: %s called with control data, which is not translated\n", fn);
        }
    }
}

ssize_t shim::sendmsg(int sockfd, const msghdr *data, int flags) {
    auto bdata = (const bionic_msghdr *) data;
    detail::sockaddr_in haddr ((const bionic::sockaddr *) bdata->msg_name, bdata->msg_namelen);
    struct ::msghdr hdata = {};
    hdata.msg_name = haddr.ptr();
    hdata.msg_namelen = haddr.ptr() ? haddr.len : 0;
    hdata.msg_iov = bdata->msg_iov;
    hdata.msg_iovlen = (int) bdata->msg_iovlen;
    if (bdata->msg_control && bdata->msg_controllen) {
        warn_control_once("sendmsg");
    }
    detail::sock_send_flags hflags (sockfd, flags);
    return ::sendmsg(sockfd, &hdata, hflags.flags);
}

ssize_t shim::recv(int sockfd, void *buf, size_t len, int flags) {
    int nflags = 0;
    if(flags & 0x4000) {
        nflags |= MSG_DONTWAIT;
    }
    if(flags & 2) {
        nflags |= MSG_PEEK;
    }
    auto ret = ::recv(sockfd, buf, len, nflags);
    netdbg_log("recv", sockfd, nullptr, ret, len, flags);
    return ret;
}

ssize_t shim::recvmsg(int sockfd, struct msghdr *data, int flags) {
    auto bdata = (bionic_msghdr *) data;
    auto name = (bionic::sockaddr *) bdata->msg_name;
    detail::sockaddr_out haddr;
    struct ::msghdr hdata = {};
    if (name) {
        hdata.msg_name = haddr.ptr();
        hdata.msg_namelen = haddr.len;
    }
    hdata.msg_iov = bdata->msg_iov;
    hdata.msg_iovlen = (int) bdata->msg_iovlen;
    if (bdata->msg_control && bdata->msg_controllen) {
        warn_control_once("recvmsg");
    }

    auto val = ::recvmsg(sockfd, &hdata, to_host_recv_flags(flags));
    netdbg_log("recvmsg", sockfd, name ? haddr.ptr() : nullptr, val, bdata->msg_controllen, flags);
    if (val >= 0) {
        if (name) {
            haddr.len = hdata.msg_namelen;
            haddr.apply(name, &bdata->msg_namelen);
        }
        bdata->msg_controllen = 0;
        bdata->msg_flags = from_host_msg_flags(hdata.msg_flags);
    }
    return val;
}

ssize_t shim::sendto(int sockfd, const void *buf, size_t len, int flags, const bionic::sockaddr *addr, socklen_t addrlen) {
    detail::sockaddr_in haddr (addr, addrlen);
    detail::sock_send_flags hflags (sockfd, flags);
    auto ret = ::sendto(sockfd, buf, len, hflags.flags, haddr.ptr(), haddr.len);
    netdbg_log("sendto", sockfd, haddr.ptr(), ret, len, flags);
    return ret;
}

ssize_t shim::recvfrom(int sockfd, void *buf, size_t len, int flags, bionic::sockaddr *addr, socklen_t *addrlen) {
    if (flags != 0 && flags != 0x4000)
        handle_runtime_error("recvfrom with unsupported flags %d", flags);
    if (addr == nullptr)
        return ::recvfrom(sockfd, buf, len, flags, nullptr, nullptr);
    detail::sockaddr_out haddr;
    int ret = ::recvfrom(sockfd, buf, len, flags, haddr.ptr(), &haddr.len);
    netdbg_log("recvfrom", sockfd, haddr.ptr(), ret, len, flags);
    if (ret >= 0)
        haddr.apply(addr, addrlen);
        return ret;
    }

int shim::getsockname(int sockfd, shim::bionic::sockaddr *addr, socklen_t *addrlen) {
    detail::sockaddr_out haddr;
    int ret = ::getsockname(sockfd, haddr.ptr(), &haddr.len);
    if (ret == 0)
        haddr.apply(addr, addrlen);
    return ret;
}

int shim::getpeername(int sockfd, shim::bionic::sockaddr *addr, socklen_t *addrlen) {
    detail::sockaddr_out haddr;
    int ret = ::getpeername(sockfd, haddr.ptr(), &haddr.len);
    if (ret == 0)
        haddr.apply(addr, addrlen);
    return ret;
}

int shim::accept(int sockfd, shim::bionic::sockaddr *addr, socklen_t *addrlen) {
    detail::sockaddr_out haddr;
    int ret = ::accept(sockfd, haddr.ptr(), &haddr.len);
    if (ret >= 0 && addrlen)
        haddr.apply(addr, addrlen);
    return ret;
}

int shim::accept4(int sockfd, shim::bionic::sockaddr *addr, socklen_t *addrlen, int flag) {
    detail::sockaddr_out haddr;
    int ret = ::accept(sockfd, haddr.ptr(), &haddr.len);
    if (ret >= 0 && addrlen)
        haddr.apply(addr, addrlen);
    return ret;
}

int shim::getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen) {
    return ::getsockopt(sockfd, bionic::to_host_sockopt_level(level), bionic::to_host_sockopt(level, optname), optval, optlen);
}

int shim::setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
    if (netdbg()) fprintf(stderr, "NETDBG setsockopt fd=%d level=%d opt=%d len=%u\n", sockfd, level, optname, optlen);
    return ::setsockopt(sockfd, bionic::to_host_sockopt_level(level), bionic::to_host_sockopt(level, optname), optval, optlen);
}

int shim::shutdown(int sockfd, int how) {
    int hhow = 0;
    switch (how) {
        case 0: hhow = SHUT_RD; break;
        case 1: hhow = SHUT_WR; break;
        case 2: hhow = SHUT_RDWR; break;
        default: handle_runtime_error("Unexpected how parameter passed to shutdown %d", how);
    }
    return ::shutdown(sockfd, hhow);
}

int shim::inet_pton(bionic::af_family af, const char *src, void *dst) {
    return ::inet_pton(bionic::to_host_af_family(af), src, dst);
}

const char * shim::inet_ntop(bionic::af_family af, const void *src, char *dst, socklen_t size) {
    return ::inet_ntop(bionic::to_host_af_family(af), src, dst, size);
}

detail::sock_send_flags::sock_send_flags(int fd, int flags) : fd(fd), src_flags(flags), flags(0) {
    if (flags & 0x4000) {
#ifdef __APPLE__
        int value = 1;
        socklen_t siz = sizeof(saved_nosigpipe);
        ::getsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &saved_nosigpipe, &siz);
        ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &value, sizeof(value));
#else
        this->flags |= MSG_NOSIGNAL;
#endif
        flags &= ~0x4000;
    }
    if (flags != 0)
        handle_runtime_error("Unexpected flags in a socket send operation %d", flags);
}

detail::sock_send_flags::~sock_send_flags() {
#ifdef __APPLE__
    if (src_flags & 0x4000)
        ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &saved_nosigpipe, sizeof(saved_nosigpipe));
#endif
}

void shim::add_network_shimmed_symbols(std::vector<shim::shimmed_symbol> &list) {
    list.insert(list.end(), {
        /* socket.h */
        {"socket", WithErrnoUpdate(socket)},
        {"bind", WithErrnoUpdate(bind)},
        {"connect", WithErrnoUpdate(connect)},
        {"send", WithErrnoUpdate(send)},
        {"sendmsg", WithErrnoUpdate(sendmsg)},
        {"sendto", WithErrnoUpdate(sendto)},
        {"recv", WithErrnoUpdate(recv)},
        {"recvmsg", WithErrnoUpdate(recvmsg)},
        {"recvfrom", WithErrnoUpdate(recvfrom)},
        {"getsockname", WithErrnoUpdate(getsockname)},
        {"getpeername", WithErrnoUpdate(getpeername)},
        {"accept", WithErrnoUpdate(accept)},
        {"accept4", WithErrnoUpdate(accept4)},
        {"getsockopt", WithErrnoUpdate(getsockopt)},
        {"setsockopt", WithErrnoUpdate(setsockopt)},
        {"listen", WithErrnoUpdate(::listen)},
        {"shutdown", WithErrnoUpdate(shutdown)},

        /* netdb.h */
        {"getaddrinfo", getaddrinfo},
        {"freeaddrinfo", freeaddrinfo},
        {"getnameinfo", getnameinfo},
        {"gai_strerror", gai_strerror},

        {"gethostbyaddr", gethostbyaddr},
        {"gethostbyname", gethostbyname},
        {"gethostbyname2", gethostbyname2},
        {"gethostent", gethostent},

        /* arpa/inet.h */
        {"inet_addr", inet_addr},
        {"inet_lnaof", inet_lnaof},
        {"inet_makeaddr", inet_makeaddr},
        {"inet_netof", inet_netof},
        {"inet_network", inet_network},
        {"inet_ntoa", inet_ntoa},
        {"inet_pton", inet_pton},
        {"inet_ntop", inet_ntop},

        /* net/if.h */
        {"if_nametoindex", if_nametoindex},
        {"if_indextoname", if_indextoname},
        {"if_nameindex", if_nameindex},
        {"if_freenameindex", if_freenameindex},
        {"getifaddrs", getifaddrs},
        {"freeifaddrs", freeifaddrs},
        {"in6addr_any", (void*)&in6addr_any},
        {"in6addr_loopback", (void*)&in6addr_loopback},
    });
}
