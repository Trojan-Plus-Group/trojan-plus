/*
 * This file is part of the Trojan Plus project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Trojan Plus is derived from original trojan project and writing
 * for more experimental features.
 * Copyright (C) 2020 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LWIP_CUSTOM_LWIPOPTS_H
#define LWIP_CUSTOM_LWIPOPTS_H

#define NO_SYS        1
#define LWIP_TIMERS   0
#define MEM_ALIGNMENT 4

#define LWIP_ARP             0
#define ARP_QUEUEING         0
#define IP_FORWARD           0
#define LWIP_ICMP            1
#define LWIP_RAW             0
#define LWIP_DHCP            0
#define LWIP_AUTOIP          0
#define LWIP_SNMP            0
#define LWIP_IGMP            0
#define LWIP_DNS             0
#define LWIP_UDP             0
#define LWIP_UDPLITE         0
#define LWIP_TCP             1
#define LWIP_CALLBACK_API    1
#define LWIP_NETIF_API       0
#define LWIP_NETIF_LOOPBACK  0
#define LWIP_HAVE_LOOPIF     0
#define LWIP_HAVE_SLIPIF     0
#define LWIP_NETCONN         0
#define LWIP_SOCKET          0
#define PPP_SUPPORT          0
#define LWIP_IPV6            1
#define LWIP_IPV6_MLD        0
#define LWIP_IPV6_AUTOCONFIG 0
#define LWIP_WND_SCALE       1
#define TCP_RCV_SCALE        5

#define MEMP_NUM_TCP_PCB_LISTEN 16
#define MEMP_NUM_TCP_PCB        1024
#ifndef TCP_MSS
#define TCP_MSS 1460
#endif // TCP_MSS
#define TCP_SND_BUF      16384
#define TCP_SND_QUEUELEN (4 * (TCP_SND_BUF) / (TCP_MSS))

#define MEM_LIBC_MALLOC 1
#define MEMP_MEM_MALLOC 1

#define LWIP_PERF            0
#define SYS_LIGHTWEIGHT_PROT 0
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS

// needed on 64-bit systems, enable it always so that the same configuration
// is used regardless of the platform
#define IPV6_FRAG_COPYHEADER 1

/*
#define LWIP_DEBUG 1
#define IP_DEBUG LWIP_DBG_ON
#define NETIF_DEBUG LWIP_DBG_ON
#define TCP_DEBUG LWIP_DBG_ON
#define TCP_INPUT_DEBUG LWIP_DBG_ON
#define TCP_OUTPUT_DEBUG LWIP_DBG_ON
*/

#endif
