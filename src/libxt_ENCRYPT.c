/**
 * xt_ENCRYPT - encrypt/decrypt the UDP payload.
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

#include "xt_ENCRYPT.h"

#include <xtables.h>
#include <stdio.h>
#include <string.h>

enum {
	O_ENCRYPT_DEENCRYPT = 0,
	O_ENCRYPT_ALGORITHM,
	O_ENCRYPT_PASSPHRASE,
	O_ENCRYPT_PERTURB_TIME,
	O_ENCRYPT_PERTURB_NUMBER,
};

#define s struct xt_encrypt_info
static const struct xt_option_entry ENCRYPT_opts[] = {
	{.name = "encrypt-decrypt", .id = O_ENCRYPT_DEENCRYPT,
	 .type = XTTYPE_NONE},
	{.name = "encrypt-algorithm", .id = O_ENCRYPT_ALGORITHM,
	 .flags = XTOPT_MAND, .type = XTTYPE_STRING, .min = 1,
	 .max = sizeof(((s *)NULL)->alg_name) - 1},
	{.name = "encrypt-passphrase", .id = O_ENCRYPT_PASSPHRASE,
	 .flags = XTOPT_MAND, .type = XTTYPE_STRING, .min = 1,
	 .max = sizeof(((s *)NULL)->passphrase) - 1},
	{.name = "encrypt-perturb-time", .id = O_ENCRYPT_PERTURB_TIME,
	 .type = XTTYPE_UINT16, .flags = XTOPT_PUT,
	 XTOPT_POINTER(s, perturb_time)},
	{.name = "encrypt-perturb-number", .id = O_ENCRYPT_PERTURB_NUMBER,
	 .type = XTTYPE_UINT16, .flags = XTOPT_PUT,
	 XTOPT_POINTER(s, perturb_number)},
	XTOPT_TABLEEND,
};
#undef s

static void ENCRYPT_help(void)
{
	printf(
"ENCRYPT target options:\n"
"--encrypt-decrypt           decrypt packets instead\n"
"--encrypt-algorithm alg     specify the encryption algorithm\n"
"--encrypt-passphrase pass   specify the passphrase\n"
"--encrypt-perturb-time sec  specify the perturb time in second\n"
"--encrypt-perturb-number n  specify the perturb number\n"
	);
}

static void ENCRYPT_parse(struct xt_option_call *cb)
{
	struct xt_encrypt_info *encrypt = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_ENCRYPT_DEENCRYPT:
		encrypt->decrypt = 1;
		break;
	case O_ENCRYPT_ALGORITHM:
		strcpy(encrypt->alg_name, cb->arg);
		break;
	case O_ENCRYPT_PASSPHRASE:
		strcpy(encrypt->passphrase, cb->arg);
		break;
	}
}

static void print_string(const char *str)
{
	char c;

	printf("\"");
	while ((c = *str++)) {
		if (c == '\\' || c == '\"')
			printf("\\%c", c);
		else
			putchar(c);
	}
	printf("\"");
}

static void ENCRYPT_print(const void *ip, const struct xt_entry_target *target,
		int numeric)
{
	const struct xt_encrypt_info *encrypt = (void *)target->data;

	printf(" encrypt-algorithm: ");
	print_string(encrypt->alg_name);
	printf(" encrypt-passphrase: ");
	print_string(encrypt->passphrase);
	if (encrypt->decrypt) {
		printf(" encrypt-decrypt");
	} else {
		if (encrypt->perturb_time)
			printf(" encrypt-perturb-time: %u",
					encrypt->perturb_time);
		if (encrypt->perturb_number)
			printf(" encrypt-perturb-number: %u",
					encrypt->perturb_number);
	}
}

static void ENCRYPT_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_encrypt_info *encrypt = (void *)target->data;

	printf(" --encrypt-algorithm ");
	print_string(encrypt->alg_name);
	printf(" --encrypt-passphrase ");
	print_string(encrypt->passphrase);
	if (encrypt->decrypt) {
		printf(" --encrypt-decrypt");
	} else {
		if (encrypt->perturb_time)
			printf(" --encrypt-perturb-time %u",
					encrypt->perturb_time);
		if (encrypt->perturb_number)
			printf(" --encrypt-perturb-number %u",
					encrypt->perturb_number);
	}
}

static struct xtables_target encrypt_tg_reg = {
	.version	= XTABLES_VERSION,
	.name		= "ENCRYPT",
	.family		= PF_INET,
	.revision	= 0,
	.size		= XT_ALIGN(sizeof(struct xt_encrypt_info)),
	.userspacesize	= offsetof(struct xt_encrypt_info, priv),
	.help		= ENCRYPT_help,
	.print		= ENCRYPT_print,
	.save		= ENCRYPT_save,
	.x6_parse	= ENCRYPT_parse,
	.x6_options	= ENCRYPT_opts,
};

void _init(void)
{
	xtables_register_target(&encrypt_tg_reg);
}
