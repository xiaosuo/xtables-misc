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

#include "xt_sip.h"

#include <xtables.h>
#include <stdio.h>

enum {
	O_SIP_SIGNAL = 0,
	O_SIP_RTP,
	O_SIP_RTCP,
	F_SIP_SIGNAL	= 1 << O_SIP_SIGNAL,
	F_SIP_RTP	= 1 << O_SIP_RTP,
	F_SIP_RTCP	= 1 << O_SIP_RTCP,
	F_SIP_ANY	= F_SIP_SIGNAL | F_SIP_RTP | F_SIP_RTCP,
};

static void sip_help(void)
{
	printf(
"sip match options:\n"
"--sip-signal  Match signal packets\n"
"--sip-rtp     Match RTP packets\n"
"--sip-rtcp    Match RTCP packets\n");
}

#define s struct xt_sip_info
static const struct xt_option_entry sip_opts[] = {
	{.name = "sip-signal", .id = O_SIP_SIGNAL, .type = XTTYPE_NONE},
	{.name = "sip-rtp", .id = O_SIP_RTP, .type = XTTYPE_NONE},
	{.name = "sip-rtcp", .id = O_SIP_RTCP, .type = XTTYPE_NONE},
	XTOPT_TABLEEND,
};
#undef s

static void sip_parse(struct xt_option_call *cb)
{
	struct xt_sip_info *info = cb->data;

	switch (cb->entry->id) {
	case O_SIP_SIGNAL:
		info->flags |= XT_F_SIP_SIGNAL;
		break;
	case O_SIP_RTP:
		info->flags |= XT_F_SIP_RTP;
		break;
	case O_SIP_RTCP:
		info->flags |= XT_F_SIP_RTCP;
		break;
	}
}

static void sip_check(struct xt_fcheck_call *cb)
{
	if (!(cb->xflags & F_SIP_ANY)) {
		struct xt_sip_info *info = cb->data;

		info->flags = XT_F_SIP_ANY;
	}
}

static void sip_print(const void *ip, const struct xt_entry_match *match,
		int numeric)
{
	const struct xt_sip_info *info = (const void *)match->data;

	printf(" SIP match");
	if (info->flags & XT_F_SIP_SIGNAL)
		printf(" SIGNAL");
	if (info->flags & XT_F_SIP_RTP)
		printf(" RTP");
	if (info->flags & XT_F_SIP_RTCP)
		printf(" RTCP");
}

static void sip_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_sip_info *info = (const void *)match->data;

	if (info->flags & XT_F_SIP_SIGNAL)
		printf(" --sip-signal");
	if (info->flags & XT_F_SIP_RTP)
		printf(" --sip-rtp");
	if (info->flags & XT_F_SIP_RTCP)
		printf(" --sip-rtcp");
}

static struct xtables_match sip_mt_reg = {
	.name		= "sip",
	.revision	= 0,
	.family		= NFPROTO_UNSPEC,
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_sip_info)),
	.userspacesize	= sizeof(struct xt_sip_info),
	.help		= sip_help,
	.print		= sip_print,
	.save		= sip_save,
	.x6_parse	= sip_parse,
	.x6_fcheck	= sip_check,
	.x6_options	= sip_opts,
};

void _init(void)
{
	xtables_register_match(&sip_mt_reg);
}
