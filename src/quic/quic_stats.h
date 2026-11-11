#ifndef TROJAN_QUIC_STATS_H
#define TROJAN_QUIC_STATS_H

// OFF erases diagnostics, including state, captures, scopes and CC selection.
// Keep production expressions identical to the historical BBR-only path.
#if TROJAN_QUIC_STATS
#define QUIC_STAT(...) __VA_ARGS__
#define QUIC_SEND(...) send_udp(__VA_ARGS__)
#define QUIC_CC_ALGO quic_cc_from_env()
#else
#define QUIC_STAT(...)
#define QUIC_SEND(...) m_endpoint.send_packet(__VA_ARGS__)
#define QUIC_CC_ALGO NGTCP2_CC_ALGO_BBR
#endif

#endif
