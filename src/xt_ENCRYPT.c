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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "xt_ENCRYPT.h"

#include <linux/module.h>
#include <linux/crypto.h>
#include <crypto/md5.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Changli Gao <xiaosuo@gmail.com>");
MODULE_DESCRIPTION("Xtables: encrypt/decrypt the UDP payload");
MODULE_ALIAS("ipt_ENCRYPT");

struct xt_encrypt_priv {
	spinlock_t			lock;
	u32				num;
	struct crypto_blkcipher		*tfm;
	u8				*iv;
	unsigned int			iv_size;
	union {
		u8			salt[4];
		u32			salt_u32;
	};
	struct hash_desc		hd;
	char				passphrase[XT_ENCRYPT_MAX_PASSPHRASE];
	unsigned int			passphrase_len;
	/* used for encryption */
	struct timer_list		perturb_timer;
};

/* Use the same algorithm as EVP_BytesToKey(3SSL) */
static int md5_gen_key_iv(struct hash_desc *hd, const char *passphrase,
		unsigned int passphrase_len, const u8 *salt, u8 *key,
		unsigned int key_len, u8 *iv, unsigned int iv_len)
{
	struct scatterlist sg[1];
	u8 md[MD5_DIGEST_SIZE];
	bool add_md = false;
	int retval, len, i;

	do {
		if ((retval = crypto_hash_init(hd)))
			goto err;
#define HASH_UPDATE(x, x_len) \
do { \
		sg_init_one(sg, x, x_len); \
		if ((retval = crypto_hash_update(hd, sg, x_len))) \
			goto err; \
} while (0)
		if (!add_md)
			add_md = true;
		else
			HASH_UPDATE(md, sizeof(md));
		HASH_UPDATE(passphrase, passphrase_len);
		HASH_UPDATE(salt, 4);
		if ((retval = crypto_hash_final(hd, md)))
			goto err;

		if (key_len > 0) {
			len = sizeof(md);
			if (len > key_len)
				len = key_len;
			memcpy(key, md, len);
			key += len;
			key_len -= len;
			i = len;
		} else {
			i = 0;
		}

		if (i < sizeof(md) && iv_len > 0) {
			len = sizeof(md) - i;
			if (len > iv_len)
				len = iv_len;
			memcpy(iv, md + i, len);
			iv += len;
			iv_len -= len;
		}
	} while (iv_len > 0);
err:
	return retval;
}

static void ____xt_encrypt_update_salt(const struct xt_encrypt_info *info,
		struct xt_encrypt_priv *priv)
{
	unsigned int key_len = crypto_blkcipher_alg(priv->tfm)->max_keysize;
	u8 key[key_len];

	if (md5_gen_key_iv(&priv->hd, priv->passphrase, priv->passphrase_len,
			   priv->salt, key, key_len, priv->iv, priv->iv_size))
		panic("Oops"); /* TODO */
	if (crypto_blkcipher_setkey(priv->tfm, key, key_len))
		panic("Oops"); /* TODO */
}

static void __xt_encrypt_update_salt(unsigned long __info)
{
	struct xt_encrypt_info *info = (struct xt_encrypt_info *)__info;
	struct xt_encrypt_priv *priv = info->priv;

	spin_lock_bh(&priv->lock);
	do {
		get_random_bytes(priv->salt, sizeof(priv->salt));
	} while (priv->salt_u32 == 0);
	____xt_encrypt_update_salt(info, priv);
	priv->num = 0;
	spin_unlock_bh(&priv->lock);

	if (info->perturb_time) {
		priv->perturb_timer.expires = jiffies + info->perturb_time * HZ;
		add_timer(&priv->perturb_timer);
	}
}

static void xt_encrypt_update_salt(const struct xt_encrypt_info *info)
{
	if (!info->perturb_time || del_timer(&info->priv->perturb_timer))
		__xt_encrypt_update_salt((unsigned long)info);
}

static struct xt_encrypt_priv *xt_encrypt_alloc_priv(
		struct xt_encrypt_info *info)
{
	struct xt_encrypt_priv *priv, *error;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv) {
		error = ERR_PTR(-ENOMEM);
		goto err;
	}
	priv->tfm = crypto_alloc_blkcipher(info->alg_name, 0, 0);
	if (IS_ERR(priv->tfm)) {
		error = (void *)priv->tfm;
		goto err2;
	}
	if (crypto_blkcipher_blocksize(priv->tfm) > 255) {
		pr_warn("The block size of %s is %u > 255\n", info->alg_name,
			crypto_blkcipher_blocksize(priv->tfm));
		error = ERR_PTR(-EINVAL);
		goto err3;
	}
	priv->iv_size = crypto_blkcipher_ivsize(priv->tfm);
	priv->iv = kmalloc(priv->iv_size, GFP_KERNEL);
	if (!priv->iv) {
		error = ERR_PTR(-ENOMEM);
		goto err3;
	}
	priv->hd.tfm = crypto_alloc_hash("md5", 0, 0);
	if (IS_ERR(priv->hd.tfm)) {
		error = (void *)priv->hd.tfm;
		goto err4;
	}
	priv->hd.flags = 0;
	strcpy(priv->passphrase, info->passphrase);
	priv->passphrase_len = strlen(priv->passphrase);
	spin_lock_init(&priv->lock);
	setup_timer(&priv->perturb_timer, __xt_encrypt_update_salt,
			(unsigned long)info);

	return priv;
err4:
	kfree(priv->iv);
err3:
	crypto_free_blkcipher(priv->tfm);
err2:
	kfree(priv);
err:
	return error;
}

static void xt_encrypt_free_priv(struct xt_encrypt_priv *priv)
{
	crypto_free_hash(priv->hd.tfm);
	kfree(priv->iv);
	crypto_free_blkcipher(priv->tfm);
	kfree(priv);
}

static int encrypt(const struct xt_encrypt_info *info,
		struct xt_encrypt_priv *priv, struct sk_buff *skb, int offset)
{
	int len = skb->len - offset;
	int block_size = crypto_blkcipher_blocksize(priv->tfm);
	int pad_len = block_size - (len % block_size);
	u8 pad;
	int nsg, retval, add_len;
	struct sk_buff *last_skb;
	struct scatterlist *sg;
	struct blkcipher_desc desc = {
		.tfm = priv->tfm,
	};
	bool update_salt = false;

	pad = pad_len;
	pad_len += 4; /* Reserve 4 bytes for the salt */

	if (skb_tailroom(skb) < pad_len)
		add_len = pad_len - skb_tailroom(skb);
	else
		add_len = 0;
	nsg = skb_cow_data(skb, add_len, &last_skb);
	if (nsg < 0) {
		retval = nsg;
		goto err;
	}
	pad_len -= 4;
	memset(__skb_put(last_skb, pad_len), pad, pad_len);

	sg = kmalloc(sizeof(*sg) * nsg, GFP_ATOMIC);
	if (!sg) {
		retval = -ENOMEM;
		goto err;
	}
	sg_init_table(sg, nsg);
	len = skb->len - offset;
	skb_to_sgvec(skb, sg, offset, len);
	spin_lock_bh(&priv->lock);
	crypto_blkcipher_set_iv(priv->tfm, priv->iv, priv->iv_size);
	retval = crypto_blkcipher_encrypt(&desc, sg, sg, len);
	memcpy(__skb_put(last_skb, 4), priv->salt, 4);
	if (retval == 0 && info->perturb_number &&
			++priv->num >= info->perturb_number)
		update_salt = true;
	spin_unlock_bh(&priv->lock);
	kfree(sg);
	if (update_salt)
		xt_encrypt_update_salt(info);
err:
	return retval;
}

static int decrypt(const struct xt_encrypt_info *info,
		struct xt_encrypt_priv *priv, struct sk_buff *skb, int offset)
{
	unsigned int len = skb->len - offset;
	unsigned int block_size = crypto_blkcipher_blocksize(priv->tfm);
	union {
		u8	v8[4];
		u32	v32;
	} salt;
	int retval, nsg;
	struct scatterlist *sg;
	struct sk_buff *last_skb;
	struct blkcipher_desc desc = {
		.tfm = priv->tfm,
	};

	if (len < block_size + 4 || (len -= 4) % block_size) {
		retval = -EINVAL;
		goto err;
	}

	/* Get the salt */
	retval = skb_copy_bits(skb, skb->len - 4, &salt, 4);
	if (retval < 0)
		goto err;
	if (salt.v32 == 0)
		goto err;

	/* last_skb is useless here, but skb_cow_data() requires it. */
	nsg = skb_cow_data(skb, 0, &last_skb);
	if (nsg < 0) {
		retval = nsg;
		goto err;
	}
	sg = kmalloc(sizeof(*sg) * nsg, GFP_ATOMIC);
	if (!sg) {
		retval = -ENOMEM;
		goto err;
	}
	sg_init_table(sg, nsg);
	skb_to_sgvec(skb, sg, offset, len);

	spin_lock_bh(&priv->lock);
	if (salt.v32 != priv->salt_u32) {
		priv->salt_u32 = salt.v32;
		____xt_encrypt_update_salt(info, priv);
	}
	crypto_blkcipher_set_iv(priv->tfm, priv->iv, priv->iv_size);
	retval = crypto_blkcipher_decrypt(&desc, sg, sg, len);
	spin_unlock_bh(&priv->lock);

	kfree(sg);
	if (retval == 0) {
		u8 pad, last_block[block_size];
		unsigned int pad_len;
		int i;

		retval = skb_copy_bits(skb, skb->len - 4 - block_size,
				last_block, block_size);
		if (retval < 0)
			goto err;
		pad = last_block[block_size - 1];
		if (pad == 0 || pad > block_size) {
			retval = -EINVAL;
			goto err;
		}
		pad_len = pad;
		i = block_size - 2;
		while (--pad_len > 0) {
			if (last_block[i--] != pad) {
				retval = -EINVAL;
				goto err;
			}
		}
		__skb_trim(skb, skb->len - pad - 4);
	}
err:
	return retval;
}

static unsigned int encrypt_tg(struct sk_buff *skb,
		const struct xt_action_param *par)
{
	const struct xt_encrypt_info *info = par->targinfo;
	struct iphdr *iph, _iph;
	struct udphdr *udph;
	unsigned int len;
	int retval;

	iph = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
	if (!iph)
		goto err;
	/**
	 * This check is redundant, since we speficy the dependency on
	 * nf_defrag_ipv4 explicitly in encrypt_tg_init().
	 */
	if (ip_is_fragment(iph))
		goto err;

	len = par->thoff + sizeof(struct udphdr);
	if (skb->len < len)
		goto err;
	if (info->decrypt)
		retval = decrypt(info, info->priv, skb, len);
	else
		retval = encrypt(info, info->priv, skb, len);
	if (retval)
		goto err;

	if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(*udph)))
		goto err;
	udph = (struct udphdr *)(skb->data + par->thoff);
	udph->len = htons(skb->len - par->thoff);
	if (udph->check) {
		udph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr,
				skb->len - par->thoff, IPPROTO_UDP, 0);
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = (unsigned char *)udph - skb->head;
		skb->csum_offset = offsetof(struct udphdr, check);
	}

	iph = ip_hdr(skb);
	iph->tot_len = htons(skb->len);
	iph->check = 0;
	iph->check = ip_fast_csum(iph, iph->ihl);

	return XT_CONTINUE;
err:
	return NF_DROP;
}

static int encrypt_tg_check(const struct xt_tgchk_param *par)
{
	struct xt_encrypt_info *info = par->targinfo;
	int len;

	if (info->decrypt & ~1)
		return -EINVAL;

	len = strnlen(info->passphrase, sizeof(info->passphrase));
	if (len == 0 || len == sizeof(info->passphrase))
		return -EINVAL;

	info->priv = xt_encrypt_alloc_priv(info);
	if (IS_ERR(info->priv))
		return PTR_ERR(info->priv);
	if (info->decrypt)
		info->priv->salt_u32 = 0;
	else
		__xt_encrypt_update_salt((unsigned long)info);

	return 0;
}

static void encrypt_tg_destroy(const struct xt_tgdtor_param *par)
{
	const struct xt_encrypt_info *info = par->targinfo;

	del_timer_sync(&info->priv->perturb_timer);
	xt_encrypt_free_priv(info->priv);
}

static struct xt_target encrypt_tg_reg __read_mostly = {
	.name		= "ENCRYPT",
	.revision	= 0,
	.family		= NFPROTO_IPV4,
	.proto		= IPPROTO_UDP,
	.target		= encrypt_tg,
	.targetsize	= sizeof(struct xt_encrypt_info),
	.checkentry	= encrypt_tg_check,
	.destroy	= encrypt_tg_destroy,
	.me		= THIS_MODULE
};

static int __init encrypt_tg_init(void)
{
	nf_defrag_ipv4_enable();

	return xt_register_target(&encrypt_tg_reg);
}

static void __exit encrypt_tg_exit(void)
{
	xt_unregister_target(&encrypt_tg_reg);
}

module_init(encrypt_tg_init);
module_exit(encrypt_tg_exit);
