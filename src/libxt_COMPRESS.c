/**
 * xt_COMPRESS - compress/decompress the UDP payload.
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

#include "xt_COMPRESS.h"

#include <xtables.h>
#include <stdio.h>
#include <string.h>

enum {
	O_COMPRESS_DECOMPRESS = 0,
	O_COMPRESS_ALGORITHM,
};

#define s struct xt_compress_info
static const struct xt_option_entry COMPRESS_opts[] = {
	{.name = "compress-decompress", .id = O_COMPRESS_DECOMPRESS,
	 .type = XTTYPE_NONE},
	{.name = "compress-algorithm", .id = O_COMPRESS_ALGORITHM,
	 .flags = XTOPT_MAND, .type = XTTYPE_STRING, .min = 1,
	 .max = sizeof(((s *)NULL)->alg_name) - 1},
	XTOPT_TABLEEND,
};
#undef s

static void COMPRESS_help(void)
{
	printf(
"COMPRESS target options:\n"
"--compress-decompress           decompress packets instead\n"
"--compress-algorithm alg        specify the compression algorithm\n"
	);
}

static void COMPRESS_parse(struct xt_option_call *cb)
{
	struct xt_compress_info *compress = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_COMPRESS_DECOMPRESS:
		compress->decompress = 1;
		break;
	case O_COMPRESS_ALGORITHM:
		strcpy(compress->alg_name, cb->arg);
		break;
	}
}

static void COMPRESS_print(const void *ip, const struct xt_entry_target *target,
		int numeric)
{
	const struct xt_compress_info *compress = (void *)target->data;

	printf(" compress-algorithm: %s", compress->alg_name);
	if (compress->decompress)
		printf(" compress-decompress");
}

static void COMPRESS_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_compress_info *compress = (void *)target->data;

	printf(" --compress-algorithm %s", compress->alg_name);
	if (compress->decompress)
		printf(" --compress-decompress");
}

static struct xtables_target compress_tg_reg = {
	.version	= XTABLES_VERSION,
	.name		= "COMPRESS",
	.family		= PF_INET,
	.revision	= 0,
	.size		= XT_ALIGN(sizeof(struct xt_compress_info)),
	.userspacesize	= offsetof(struct xt_compress_info, tfm),
	.help		= COMPRESS_help,
	.print		= COMPRESS_print,
	.save		= COMPRESS_save,
	.x6_parse	= COMPRESS_parse,
	.x6_options	= COMPRESS_opts,
};

void _init(void)
{
	xtables_register_target(&compress_tg_reg);
}
