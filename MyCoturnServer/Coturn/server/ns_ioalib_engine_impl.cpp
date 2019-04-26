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

 
#include "../common/ns_ioalib_impl.h"
 
#if !defined(TURN_NO_SCTP) && defined(TURN_SCTP_INCLUDE)
#include TURN_SCTP_INCLUDE
#endif

 /* Compilation test:
 #if defined(IP_RECVTTL)
 #undef IP_RECVTTL
 #endif
 #if defined(IPV6_RECVHOPLIMIT)
 #undef IPV6_RECVHOPLIMIT
 #endif
 #if defined(IP_RECVTOS)
 #undef IP_RECVTOS
 #endif
 #if defined(IPV6_RECVTCLASS)
 #undef IPV6_RECVTCLASS
 #endif
 */

#define MAX_ERRORS_IN_UDP_BATCH (1024)

struct turn_sock_extended_err {
	uint32_t ee_errno; /* error number */
	uint8_t ee_origin; /* where the error originated */
	uint8_t ee_type; /* type */
	uint8_t ee_code; /* code */
	uint8_t ee_pad; /* padding */
	uint32_t ee_info; /* additional information */
	uint32_t ee_data; /* other data */
/* More data may follow */
};

#define TRIAL_EFFORTS_TO_SEND (2)

#define SSL_MAX_RENEG_NUMBER (3)

const int predef_timer_intervals[PREDEF_TIMERS_NUM] = { 30,60,90,120,240,300,360,540,600,700,800,900,1800,3600 };

/************** Forward function declarations ******/

ioa_engine_handle create_ioa_engine(turnipports *tp, const s08bits* relay_ifname,
	size_t relays_number, s08bits **relay_addrs, int default_relays,
	int verbose
#if !defined(TURN_NO_HIREDIS)
	, const char* redis_report_connection_string
#endif
)
{
	static int capabilities_checked = 0;

	if (!capabilities_checked) {
		capabilities_checked = 1;
#if !defined(CMSG_SPACE)
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "On this platform, I am using alternative behavior of TTL/TOS according to RFC 5766.\n");
#endif
#if !defined(IP_RECVTTL) || !defined(IP_TTL)
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "IPv4: On this platform, I am using alternative behavior of TTL according to RFC 5766.\n");
#endif
#if !defined(IPV6_RECVHOPLIMIT) || !defined(IPV6_HOPLIMIT)
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "IPv6: On this platform, I am using alternative behavior of TTL (HOPLIMIT) according to RFC 6156.\n");
#endif
#if !defined(IP_RECVTOS) || !defined(IP_TOS)
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "IPv4: On this platform, I am using alternative behavior of TOS according to RFC 5766.\n");
#endif
#if !defined(IPV6_RECVTCLASS) || !defined(IPV6_TCLASS)
		TURN_LOG_FUNC(TURN_LOG_LEVEL_WARNING, "IPv6: On this platform, I am using alternative behavior of TRAFFIC CLASS according to RFC 6156.\n");
#endif
	}

	if (!relays_number || !relay_addrs || !tp) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Cannot create TURN engine\n", __FUNCTION__);
		return NULL;
	}
	else {
		ioa_engine_handle e = (ioa_engine_handle)malloc(sizeof(ioa_engine));

		e->sm = sm;
		e->default_relays = default_relays;
		e->verbose = verbose;
		e->tp = tp;
		if (eb) {
			e->event_base = eb;
			e->deallocate_eb = 0;
		}
		else {
			//e->event_base = turn_event_base_new();
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "IO method (engine own thread): %s\n", event_base_get_method(e->event_base));
			e->deallocate_eb = 1;
		}

 

		/*{
			int t;
			for (t = 0; t < PREDEF_TIMERS_NUM; ++t) {
				struct timeval duration;
				duration.tv_sec = predef_timer_intervals[t];
				duration.tv_usec = 0;
				const struct timeval *ptv = event_base_init_common_timeout(e->event_base, &duration);
				if (!ptv) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "FATAL: cannot create preferable timeval for %d secs (%d number)\n", predef_timer_intervals[t], t);
					exit(-1);
				}
				else {
					ns_bcopy(ptv, &(e->predef_timers[t]), sizeof(struct timeval));
					e->predef_timer_intervals[t] = predef_timer_intervals[t];
				}
			}
		}*/


		if (relay_ifname) {
			STRCPY(e->relay_ifname, relay_ifname);
		}
			

		{
			size_t i = 0;
			/*e->relay_addrs = (ioa_addr*)allocate_super_memory_region(sm, relays_number * sizeof(ioa_addr) + 8);*/
			for (i = 0; i < relays_number; i++) {
				if (make_ioa_addr((u08bits*)relay_addrs[i], 0, &(e->relay_addrs[i])) < 0) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Cannot add a relay address: %s\n", relay_addrs[i]);
				}
			}
			e->relays_number = relays_number;
		}
		e->relay_addr_counter = (unsigned short)turn_random();
		//timer_handler(e, e);
		//e->timer_ev = set_ioa_timer(e, 1, 0, timer_handler, e, 1, "timer_handler");
		return e;
	}
}
 
/************** Utils **************************/

static const int tcp_congestion_control = 1;
 

void ioa_network_buffer_set_size(ioa_network_buffer_handle nbh, size_t len)
{
	stun_buffer_list_elem *buf_elem = (stun_buffer_list_elem *)nbh;
	buf_elem->buf.len = (size_t)len;
}
 

//////////////////////////////////////////////////
