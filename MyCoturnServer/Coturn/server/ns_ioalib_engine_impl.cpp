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

 
/************** Utils **************************/

static const int tcp_congestion_control = 1;
 

void ioa_network_buffer_set_size(ioa_network_buffer_handle nbh, size_t len)
{
	stun_buffer_list_elem *buf_elem = (stun_buffer_list_elem *)nbh;
	buf_elem->buf.len = (size_t)len;
}
 

//////////////////////////////////////////////////