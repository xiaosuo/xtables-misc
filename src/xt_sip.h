/**
 * xt_sip - match SIP packets.
 * Copyright (C) 2013 Changli Gao <xiaosuo@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _XT_SIP_H
#define _XT_SIP_H

#include <linux/types.h>

enum {
	XT_SIP_SIGNAL = 0,
	XT_SIP_RTP,
	XT_SIP_RTCP,
	XT_F_SIP_SIGNAL	= 1 << XT_SIP_SIGNAL,
	XT_F_SIP_RTP	= 1 << XT_SIP_RTP,
	XT_F_SIP_RTCP	= 1 << XT_SIP_RTCP,
	XT_F_SIP_ANY	= XT_F_SIP_SIGNAL | XT_F_SIP_RTP | XT_F_SIP_RTCP,
};

struct xt_sip_info {
	__u8	flags;
};

#endif /* _XT_SIP_H */
