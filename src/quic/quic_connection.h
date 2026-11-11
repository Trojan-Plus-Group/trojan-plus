/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef _QUIC_CONNECTION_H_
#define _QUIC_CONNECTION_H_

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

#include <boost/asio/basic_waitable_timer.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <list>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include "mem/memallocator.h"
#include "quic_stream_handler.h"
#include "quic_clock.h"
#include "quic_stats.h"
#include <quic_stats_config.h>

class QuicEndpoint;
class QuicTlsCtx;
class QuicProxySession;
class QuicToHttp3Connect;
class ReadBufWithGuard;

#include <openssl/ssl.h>

// One ngtcp2_conn + its per-connection TLS handle.
// All I/O is driven through the owning QuicEndpoint's UDP socket.
class QuicConnection : public std::enable_shared_from_this<QuicConnection> {
  public:
    using IoHandler = std::function<void(boost::system::error_code, std::size_t)>;

    QuicConnection(QuicEndpoint& endpoint, std::shared_ptr<QuicTlsCtx> tls_ctx,
                   const boost::asio::ip::udp::endpoint& peer);
    ~QuicConnection();
    static uint64_t live_count() { return s_live_count.load(std::memory_order_relaxed); }

  private:
    inline static std::atomic<uint64_t> s_live_count{0};

  public:

    QuicConnection(const QuicConnection&)            = delete;
    QuicConnection& operator=(const QuicConnection&) = delete;

    // Initialise as a server connection. First packet bytes must be passed so
    // that ngtcp2 can process the Client Initial. If out_sv_scid is non-null,
    // the server's chosen SCID (sv_scid) is written there; callers should also
    // insert the connection into their routing table under that key so that
    // post-handshake packets (DCID = sv_scid) are dispatched correctly.
    bool init_server(const uint8_t* data, std::size_t datalen,
                     const boost::asio::ip::udp::endpoint& local_ep,
                     const boost::asio::ip::udp::endpoint& remote_ep,
                     const ngtcp2_cid* dcid, const ngtcp2_cid* scid,
                     uint32_t version,
                     ngtcp2_cid* out_sv_scid = nullptr);

    // Initialise as a client connection and start the QUIC handshake.
    bool init_client(const boost::asio::ip::udp::endpoint& local_ep,
                     const boost::asio::ip::udp::endpoint& remote_ep);

    // Feed an incoming UDP datagram to ngtcp2.
    void on_packet(const uint8_t* data, std::size_t datalen,
                   const boost::asio::ip::udp::endpoint& local_ep,
                   const boost::asio::ip::udp::endpoint& remote_ep);

    void on_pump_write(const char* debug_path);
    void probe();
    QuicClock::time_point last_packet_received() const { return m_last_packet_received; }

    // called by QuicProxySession, this func has re-try timer and ack-delay mechanisms 
    void send_stream_data(int64_t stream_id, std::shared_ptr<ReadBufWithGuard> buf, bool fin, IoHandler sent_cb);

    // Called by H3, which owns retries and ACKs. accepted also distinguishes
    // an accepted empty FIN (true, 0 bytes) from backpressure (false, 0 bytes).
    int64_t send_stream_vecs(int64_t stream_id, const ngtcp2_vec* datav, std::size_t datavcnt, bool fin, bool& accepted, const char* debug_path);
    
    // Open a new server-initiated unidirectional stream (for H3 control/QPACK).
    // Returns the stream ID, or -1 on error.
    int64_t open_uni_stream();

    int open_bidi_stream(int64_t& stream_id);

    // Handler management
    void set_stream_handler(int64_t stream_id, std::shared_ptr<QuicStreamHandler> handler);
    void remove_stream_handler(int64_t stream_id);

    // H3 manager — lazily created on first H3 stream; null until then.
    QuicToHttp3Connect& get_or_create_h3();
    [[nodiscard]] QuicToHttp3Connect* h3_if_exists() const { return m_h3.get(); }

    // Forward a stream to HTTP/3 upstream. Returns true on success.
    [[nodiscard]] bool forward_to_h1_upstream(int64_t stream_id, const uint8_t* data, std::size_t len, bool fin);

    // Gracefully close the connection with an optional application error code.
    void close(uint64_t app_error_code = 0);

    // Manually extend the QUIC flow control window for a stream.
    // Call this after the application has processed/sent received data.
     void stream_extend_window(int64_t stream_id, std::size_t n);
    void conn_extend_window(std::size_t n);

    void on_extend_max_stream_data(int64_t stream_id, uint64_t max_data);
    [[nodiscard]] bool is_stream_flow_control_blocked(int64_t stream_id) const;

    // Manually reset a stream with an error code.
    void reset_stream(int64_t stream_id, uint64_t app_error_code);
    void stop_reading_stream(int64_t stream_id, uint64_t app_error_code);

    [[nodiscard]] bool is_closed() const { return m_closed; }
    [[nodiscard]] bool is_handshake_done() const { return m_handshake_done; }
    [[nodiscard]] const boost::asio::ip::udp::endpoint& peer() const { return m_peer; }
    [[nodiscard]] ngtcp2_conn* native_handle() const { return m_conn; }

    enum class ConnType { unknown, proxy, other };
    [[nodiscard]] ConnType conn_type() const { return m_conn_type; }
    void set_conn_type(ConnType t) { m_conn_type = t; }

    static constexpr size_t kServerScidLen = 18;

    // Callback invoked on handshake completion (client: after server Finished).
    std::function<void()> on_handshake_completed_cb;
    // Callback invoked when stream data arrives (stream_id, data, len, fin).
    std::function<void(int64_t, const uint8_t*, std::size_t, bool)> on_stream_data_cb;
    // Callback invoked when a new remote-initiated stream is opened.
    std::function<void(int64_t)> on_stream_open_cb;
    // Callback invoked when a stream is closed.
    std::function<void(int64_t)> on_stream_close_cb;
    // Callback invoked when a new Connection ID is generated.
    std::function<void(const ngtcp2_cid*)> on_new_connection_id_cb;
    // Callback invoked when connection closes.
    std::function<void(QuicConnection*)> on_close_cb;
    // Callback invoked when peer extends max streams (client: can open more bidi streams).
    std::function<void()> on_extend_max_streams_cb;

  private:
    // ngtcp2 static callbacks — forward to instance methods.
    static int cb_recv_client_initial(ngtcp2_conn*, const ngtcp2_cid* dcid, void* user_data);
    static int cb_recv_crypto_data(ngtcp2_conn*, ngtcp2_encryption_level level,
                                   uint64_t offset, const uint8_t* data, size_t datalen, void* user_data);
    static int cb_handshake_completed(ngtcp2_conn*, void* user_data);
    static int cb_recv_stream_data(ngtcp2_conn*, uint32_t flags, int64_t stream_id,
                                   uint64_t offset, const uint8_t* data, std::size_t datalen,
                                   void* user_data, void* stream_user_data);
    static int cb_acked_stream_data_offset(ngtcp2_conn* conn, int64_t stream_id,
                                           uint64_t offset, uint64_t datalen,
                                           void* user_data, void* stream_user_data);
    static int cb_stream_open(ngtcp2_conn*, int64_t stream_id, void* user_data);
    static int cb_stream_close(ngtcp2_conn*, uint32_t flags, int64_t stream_id,
                               uint64_t app_error_code, void* user_data, void* stream_user_data);
    static void cb_rand(uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx* rand_ctx);
    static int cb_get_new_connection_id(ngtcp2_conn*, ngtcp2_cid* cid,
                                        ngtcp2_stateless_reset_token* token,
                                        size_t cidlen, void* user_data);
    static int cb_update_key(ngtcp2_conn*, uint8_t* rx_secret, uint8_t* tx_secret,
                             ngtcp2_crypto_aead_ctx* rx_aead_ctx, uint8_t* rx_iv,
                             ngtcp2_crypto_aead_ctx* tx_aead_ctx, uint8_t* tx_iv,
                             const uint8_t* current_rx_secret, const uint8_t* current_tx_secret,
                             size_t secretlen, void* user_data);
    static int cb_extend_max_local_streams_bidi(ngtcp2_conn*, uint64_t max_streams, void* user_data);
    static int cb_extend_max_stream_data(ngtcp2_conn* conn, int64_t stream_id,
                                         uint64_t max_data, void* user_data,
                                         void* stream_user_data);

    // ngtcp2_crypto_conn_ref get_conn callback.
    static ngtcp2_conn* get_conn_cb(ngtcp2_crypto_conn_ref* ref);

    // Internal helpers.
    ngtcp2_path make_path(const boost::asio::ip::udp::endpoint& local_ep,
                          const boost::asio::ip::udp::endpoint& remote_ep);
    void reschedule_loss_timer();
    void resume_blocked_sends();
    void schedule_send_wakeup();
#ifdef TROJAN_QUIC_STATS_LAYOUT
    // Attribution is synchronous; nested scopes restore the caller's trigger.
    // ack requires an ACKed-stream callback or observed bytes_in_flight reduction;
    // loss means aggregate ngtcp2 timer wakeup, not proven loss/PTO alone.
    // flow means explicit local/peer window event; other includes startup/probes.
    // A coalesced posted wakeup retains its first scheduling trigger.
    // Application callbacks run under their enclosing trigger; later independent
    // submissions enter application. Packets may mix frames from several causes.
    enum class SendReason { other, ack, retry, loss, application, flow, count };
    struct StatsReasonScope {
        QuicConnection* conn;
        SendReason previous{SendReason::other};
        StatsReasonScope(QuicConnection& c, SendReason reason) : conn(c.m_stats.m_stats_enabled ? &c : nullptr) {
            if (conn) { previous = conn->m_stats.m_stats_reason; conn->m_stats.m_stats_reason = reason; }
        }
        ~StatsReasonScope() { if (conn) conn->m_stats.m_stats_reason = previous; }
    };
#endif
    bool m_send_wakeup_pending{false};
    bool m_resuming_sends{false};
    QuicClock::time_point m_last_packet_received{QuicClock::now()};
    void on_handshake_completed_impl();


    // Write pending stream data (call after every read or timer event).
    void pump_write(const char* debug_path);

#ifdef TROJAN_QUIC_STATS_LAYOUT
    // UDP send for this connection. Counts send failures only when stats sampling is on.
    void send_udp(const boost::asio::ip::udp::endpoint& dest, const uint8_t* data, std::size_t len);

    // TROJAN_QUIC_STATS sampler. Armed only when the env var is set.
    void start_stats_sampler();
    void arm_stats_timer();
    void write_stats_sample(bool final_sample);
    std::size_t stats_app_queue_bytes(int64_t& stream_id, bool& have_stream) const;
    

#endif

    // Send data on an existing bidi stream. Returns false on error.
    int64_t send_stream_data_impl(int64_t stream_id, const uint8_t* data, std::size_t datalen, bool fin);

    // Send vectorised stream data sourced from nghttp3 (multi-vec variant).
    // Returns pdatalen (bytes accepted by ngtcp2), 0 if flow-controlled, -1 on error.
    int64_t send_stream_vecs_impl(int64_t stream_id, const ngtcp2_vec* datav, std::size_t datavcnt, bool fin, bool& accepted, const char* debug_path);

    QuicEndpoint& m_endpoint;
    std::shared_ptr<QuicTlsCtx> m_tls_ctx;
    boost::asio::ip::udp::endpoint m_peer;
    boost::asio::basic_waitable_timer<QuicClock, QuicWaitTraits> m_loss_timer;

    ngtcp2_conn* m_conn{nullptr};
    SSL* m_ssl{nullptr};
    ngtcp2_crypto_conn_ref m_conn_ref{};

    // sockaddr storage for local/remote addresses (kept alive for path lifetime).
    ngtcp2_sockaddr_union m_local_su{};
    ngtcp2_sockaddr_union m_remote_su{};
    ngtcp2_socklen m_local_len{0};
    ngtcp2_socklen m_remote_len{0};

    bool m_closed{false};
    bool m_handshake_done{false};
    bool m_is_server{false};
    ConnType m_conn_type{ConnType::unknown};
    uint64_t m_last_timer_expiry{0};
    // Per-connection backpressure counters are emitted once during destruction.
    uint64_t m_partial_write_retries{0};
    uint64_t m_write_more_count{0};
    uint64_t m_stream_data_blocked_count{0};

    struct UnackedBuf : public std::enable_shared_from_this<UnackedBuf>{
      int64_t m_stream_id;
      std::size_t m_ack_offset;
      std::size_t m_bytes_acked;
      std::shared_ptr<ReadBufWithGuard> m_buf;
      bool m_fin;
      IoHandler m_sent_cb;
      boost::asio::steady_timer m_write_timer;
      std::weak_ptr<QuicConnection> m_conn;
      bool m_timer_running{false};
      uint64_t m_timer_generation{0};
      std::size_t m_retry_delay_ms{50};
      UnackedBuf(boost::asio::io_context& io_ctx):m_write_timer(io_ctx), m_timer_running(false), m_retry_delay_ms(50){}
      void send();
      void cancel_timer();
      void complete(const boost::system::error_code& ec, std::size_t n);
      bool is_sending() const;
      std::size_t m_sending_offset{0};
    };
    
    // reserve un-acked buffer until ack 
    struct UnackedBuffers{
      tp::list<std::shared_ptr<UnackedBuf>> buffers;
      std::size_t curr_written{0};
      bool m_sending{false};
    };

    void fail_unacked_buffers(int64_t stream_id, const boost::system::error_code& ec);
    void fail_all_unacked_buffers(const boost::system::error_code& ec);
    void send_next_unacked_buff(int64_t stream_id, UnackedBuf* buf_finished);

    tp::unordered_map<int64_t, std::shared_ptr<QuicStreamHandler>> m_stream_handlers;
    tp::unordered_map<int64_t, std::shared_ptr<UnackedBuffers>> m_conn_unacked_bufs;
    std::unique_ptr<QuicToHttp3Connect> m_h3;  // declared after m_stream_handlers, destroyed first
    tp::vector<uint8_t> m_write_buf;
    bool m_in_read_pkt{false};
    bool m_in_pump_write{false};

#ifdef TROJAN_QUIC_STATS_LAYOUT
    void stats_zero_write_expiry();
    void stats_observe_gap(bool sent);
    struct StatsState {
        bool m_stats_read_flow{false};
        bool m_stats_read_ack{false};
        SendReason m_stats_reason{SendReason::other};
        SendReason m_stats_wakeup_reason{SendReason::other};
        // Stats sampler state. m_stats_enabled is a cached env check; the timer stays disarmed when unset.
        bool m_stats_enabled{false};
        bool m_stats_armed{false};
        bool m_stats_final_written{false};
        bool m_stats_have_stream{false};
        int64_t m_stats_stream_id{-1};
        uint64_t m_zero_len_sends{0};
        uint64_t m_udp_send_errors{0};
        // Cumulative loop entries and successful UDP datagrams, not QUIC frames.
        struct ReasonStats { uint64_t pump{0}, data{0}, vecs{0}, packets{0}; };
        ReasonStats m_reason_stats[static_cast<unsigned>(SendReason::count)]{};
        // Successful retry expiries classified by actual successful UDP sends during
        // the synchronous retry (including nested pumps/callbacks), not pending bytes.
        // Positive includes control packets/empty FIN; empty means no UDP send success.
        uint64_t m_retry_arms{0}, m_retry_expires_bytes{0}, m_retry_expires_empty{0};
        // Gap eligibility is observed at writes/samples, not continuously proven:
        // unsent UnackedBuf bytes on at least one stream with positive stream and
        // connection credit, and bytes_in_flight < cwnd. Excludes H3-owned queues,
        // FIN-only work and pacing eligibility. Any successful UDP datagram ends a
        // gap, even control-only traffic. A closed observation discards its tail.
        // Reset baseline and maximum each sample; includes unfinished gaps at sample time.
        uint64_t m_open_gap_start{0}, m_open_gap_max{0};
        uint64_t m_stats_udp_sent{0};
        // Remaining aggregate expiry at a zero packet write, not pacing evidence.
        // Last snapshot and maximum reset each sample; UINT64_MAX means no deadline.
        uint64_t m_zero_write_expiry_last{UINT64_MAX}, m_zero_write_expiry_max{0};
        // ngtcp2 exposes aggregate expiry, not pacing.next_ts: zero writes and timer
        // expiries cannot be labelled pacing-blocked without guessing. No such counters.
        std::chrono::steady_clock::time_point m_stats_origin{};
        std::unique_ptr<boost::asio::steady_timer, tp::tj_deleter<boost::asio::steady_timer>> m_stats_timer;

    } m_stats;
#endif

};

#endif // _QUIC_CONNECTION_H_
