/*
 * Copyright (C) 2011, 2012, 2013 Citrix Systems
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * IO Abstraction library
 */

#ifndef __IOA_LIBIMPL__
#define __IOA_LIBIMPL__
  
#include "ns_turn_openssl.h"

#include "ns_turn_ioalib.h"
#include "../server/turn_ports.h"
#include "ns_turn_maps_rtcp.h"
#include "ns_turn_maps.h"
#include "ns_turn_server.h"
 
#include "stun_buffer.h"  

#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

//////////////////////////////////////////////////////

#define MAX_BUFFER_QUEUE_SIZE_PER_ENGINE (64)
#define MAX_SOCKET_BUFFER_BACKLOG (16)

#define BUFFEREVENT_HIGH_WATERMARK (128<<10)
#define BUFFEREVENT_MAX_UDP_TO_TCP_WRITE (64<<9)
#define BUFFEREVENT_MAX_TCP_TO_TCP_WRITE (192<<10)

typedef struct _stun_buffer_list_elem {
	struct _stun_buffer_list_elem *next;
	stun_buffer buf;
} stun_buffer_list_elem;

typedef struct _stun_buffer_list {
	stun_buffer_list_elem *head;
	size_t tsz;
} stun_buffer_list;

/*
 * New connection callback
 */

struct cb_socket_message {
	turnserver_id id;
	tcp_connection_id connection_id;
	stun_tid tid;
	ioa_socket_handle s;
	int message_integrity;
	ioa_net_data nd;
	int can_resume;
};

struct cancelled_session_message {
	turnsession_id id;
};

struct relay_server {
	turnserver_id id; 
	struct event_base* event_base;
	struct bufferevent *in_buf;
	struct bufferevent *out_buf;
	struct bufferevent *auth_in_buf;
	struct bufferevent *auth_out_buf;
	ioa_engine_handle ioa_eng;
	turn_turnserver server;
	pthread_t thr;
};

struct message_to_relay {
	MESSAGE_TO_RELAY_TYPE t;
	struct relay_server *relay_server;
	union {
		struct socket_message sm;
		struct cb_socket_message cb_sm;
		struct cancelled_session_message csm;
	} m;
};

struct relay_server;
typedef struct relay_server *relay_server_handle;

typedef int (*ioa_engine_new_connection_event_handler)(ioa_engine_handle e, struct message_to_relay *sm);
typedef int (*ioa_engine_udp_event_handler)(relay_server_handle rs, struct message_to_relay *sm);


struct _super_memory;
typedef struct _super_memory super_memory_t;

#define TURN_CMSG_SZ (65536)

#define PREDEF_TIMERS_NUM (14)
extern const int predef_timer_intervals[PREDEF_TIMERS_NUM];

struct _ioa_engine
{
  super_memory_t *sm;
  struct event_base *event_base;
  int deallocate_eb;
  int verbose;
  turnipports* tp;
  rtcp_map *map_rtcp;
  stun_buffer_list bufs;
  SSL_CTX *tls_ctx_ssl23;
  SSL_CTX *tls_ctx_v1_0;
#if TLSv1_1_SUPPORTED
  SSL_CTX *tls_ctx_v1_1;
#if TLSv1_2_SUPPORTED
  SSL_CTX *tls_ctx_v1_2;
#endif
#endif
#if DTLS_SUPPORTED
  SSL_CTX *dtls_ctx;
#endif
#if DTLSv1_2_SUPPORTED
  SSL_CTX *dtls_ctx_v1_2;
#endif
  turn_time_t jiffie; /* bandwidth check interval */
  ioa_timer_handle timer_ev;
  s08bits cmsg[TURN_CMSG_SZ+1];
  int predef_timer_intervals[PREDEF_TIMERS_NUM];
  struct timeval predef_timers[PREDEF_TIMERS_NUM];
  /* Relays */
  s08bits relay_ifname[1025];
  int default_relays;
  size_t relays_number;
  size_t relay_addr_counter;
  ioa_addr *relay_addrs; 
};

#define SOCKET_MAGIC (0xABACADEF)

struct traffic_bytes {
	band_limit_t jiffie_bytes_read;
	band_limit_t jiffie_bytes_write;
};

struct _ioa_socket
{ 
	struct _ioa_socket *parent_s;
	u32bits magic;
	ur_addr_map *sockets_container; /* relay container for UDP sockets */
	struct bufferevent *bev;
	ioa_network_buffer_handle defer_nbh;
	int family;
	SOCKET_TYPE st;
	SOCKET_APP_TYPE sat;
	SSL* ssl;
	u32bits ssl_renegs;
	int in_write;
	int bound;
	int local_addr_known;
	ioa_addr local_addr;
	int connected;
	ioa_addr remote_addr;
	ioa_engine_handle e;
	struct event *read_event;
	ioa_net_event_handler read_cb;
	void *read_ctx;
	int done;
	ts_ur_super_session* session;
	int current_df_relay_flag;
	/* RFC6156: if IPv6 is involved, do not use DF: */
	int do_not_use_df;
	int tobeclosed;
	int broken;
	int default_ttl;
	int current_ttl;
	int default_tos;
	int current_tos;
	stun_buffer_list bufs;
	turn_time_t jiffie; /* bandwidth check interval */
	struct traffic_bytes data_traffic;
	struct traffic_bytes control_traffic;
	/* RFC 6062 ==>> */
	//Connection session:
	tcp_connection *sub_session;
	//Connect:
	struct bufferevent *conn_bev;
	connect_cb conn_cb;
	void *conn_arg;
	//Accept:
	struct evconnlistener *list_ev;
	accept_cb acb;
	void *acbarg;
	/* <<== RFC 6062 */
	void *special_session;
	size_t special_session_size;
};

typedef struct _timer_event
{
	struct event *ev;
	ioa_engine_handle e;
	ioa_timer_event_handler cb;
	void *ctx;
	s08bits* txt;
} timer_event;

///////////////////////////////////

ioa_engine_handle create_ioa_engine(turnipports* tp,
	const s08bits* relay_if,
	size_t relays_number, s08bits **relay_addrs, int default_relays,
	int verbose
#if !defined(TURN_NO_HIREDIS)
	, const char* redis_report_connection_string
#endif
);
///////////////////////// SUPER MEMORY ////////

#define allocate_super_memory_engine(e,size) allocate_super_memory_engine_func(e, size, __FILE__, __FUNCTION__, __LINE__)
void* allocate_super_memory_engine_func(ioa_engine_handle e, size_t size, const char* file, const char* func, int line);

/////////////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif /* __IOA_LIBIMPL__ */
