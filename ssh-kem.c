#include "includes.h"

#include <sys/types.h>

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "digest.h"
#include "hmac.h"
#include "kex.h"
#include "log.h"
#include "openbsd-compat/base64.h"
#include "packet.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "ssh2.h"
#include "ssherr.h"
#include "ssh-kem.h"
#include "xmalloc.h"

#include "oqs/oqs.h"

struct sshkem {
	const char *name;
	OQS_KEM *oqs;
};

struct ssh_kem_identity {
	char *alg;
	u_char *public_key;
	size_t public_key_len;
	u_char *secret_key;
	size_t secret_key_len;
};

static void
ssh_kem_trim(char *line)
{
	char *end;

	while (isspace((u_char)*line))
		line++;
	end = line + strlen(line);
	while (end > line && isspace((u_char)end[-1]))
		*--end = '\0';
}

const char *
ssh_kem_normalize_name(const char *name)
{
    if (name == NULL)
        return NULL;

    if (strcmp(name, SSH_KEM_ALG_MLKEM512) == 0)
        return SSH_KEM_ALG_MLKEM512;

    if (strcmp(name, SSH_KEM_DEFAULT_ALG) == 0)
        return SSH_KEM_DEFAULT_ALG;

    if (strcmp(name, SSH_KEM_ALG_MLKEM1024) == 0)
        return SSH_KEM_ALG_MLKEM1024;

    return NULL;
}

const char *
ssh_kem_public_key_format(const char *alg)
{
    if (alg == NULL)
        return NULL;

    if (strcmp(alg, SSH_KEM_ALG_MLKEM512) == 0)
        return SSH_KEM_KEY_FORMAT_MLKEM512;

    if (strcmp(alg, SSH_KEM_DEFAULT_ALG) == 0)
        return SSH_KEM_KEY_FORMAT_MLKEM768;

    if (strcmp(alg, SSH_KEM_ALG_MLKEM1024) == 0)
        return SSH_KEM_KEY_FORMAT_MLKEM1024;

    return NULL;
}

int
ssh_kem_encode_public_key_blob(const char *alg,
    const u_char *public_key, size_t public_key_len,
    struct sshbuf **blobp)
{
    struct sshkem *kem = NULL;
    struct sshbuf *blob = NULL;
    const char *format;
    int r = SSH_ERR_INVALID_ARGUMENT;

    if (blobp != NULL)
        *blobp = NULL;

    if (alg == NULL || public_key == NULL || blobp == NULL)
        return SSH_ERR_INVALID_ARGUMENT;

    format = ssh_kem_public_key_format(alg);
    if (format == NULL || (kem = ssh_kem_new(alg)) == NULL)
        return SSH_ERR_INVALID_ARGUMENT;

    if (public_key_len != ssh_kem_public_key_len(kem)) {
        r = SSH_ERR_INVALID_FORMAT;
        goto out;
    }

    if ((blob = sshbuf_new()) == NULL) {
        r = SSH_ERR_ALLOC_FAIL;
        goto out;
    }

    if ((r = sshbuf_put_cstring(blob, format)) != 0 ||
        (r = sshbuf_put_string(blob,
        public_key, public_key_len)) != 0)
        goto out;

    *blobp = blob;
    blob = NULL;
    r = 0;

out:
    sshbuf_free(blob);
    ssh_kem_free(kem);
    return r;
}

int
ssh_kem_decode_public_key_blob(const char *alg,
    const u_char *blob, size_t blob_len,
    u_char **public_keyp, size_t *public_key_lenp)
{
    struct sshkem *kem = NULL;
    struct sshbuf *b = NULL;
    const char *format;
    const u_char *wire_format = NULL, *wire_key = NULL;
    u_char *key = NULL;
    size_t wire_format_len = 0, wire_key_len = 0;
    size_t expected_len;
    int r = SSH_ERR_INVALID_FORMAT;

    if (public_keyp != NULL)
        *public_keyp = NULL;
    if (public_key_lenp != NULL)
        *public_key_lenp = 0;

    if (alg == NULL || blob == NULL ||
        public_keyp == NULL || public_key_lenp == NULL)
        return SSH_ERR_INVALID_ARGUMENT;

    format = ssh_kem_public_key_format(alg);
    if (format == NULL || (kem = ssh_kem_new(alg)) == NULL)
        return SSH_ERR_INVALID_ARGUMENT;

    /* Two SSH strings: format identifier and raw KEM public key. */
    expected_len = 8 + strlen(format) +
        ssh_kem_public_key_len(kem);

    if (blob_len != expected_len)
        goto out;

    if ((b = sshbuf_from(blob, blob_len)) == NULL) {
        r = SSH_ERR_ALLOC_FAIL;
        goto out;
    }

    if ((r = sshbuf_get_string_direct(b,
        &wire_format, &wire_format_len)) != 0 ||
        (r = sshbuf_get_string_direct(b,
        &wire_key, &wire_key_len)) != 0)
        goto out;

    /* Require an exact format match and no trailing bytes. */
    if (wire_format_len != strlen(format) ||
        memcmp(wire_format, format, wire_format_len) != 0 ||
        wire_key_len != ssh_kem_public_key_len(kem) ||
        sshbuf_len(b) != 0) {
        r = SSH_ERR_INVALID_FORMAT;
        goto out;
    }

    if ((key = malloc(wire_key_len)) == NULL) {
        r = SSH_ERR_ALLOC_FAIL;
        goto out;
    }

    memcpy(key, wire_key, wire_key_len);

    *public_keyp = key;
    *public_key_lenp = wire_key_len;
    key = NULL;
    r = 0;

out:
    free(key);
    sshbuf_free(b);
    ssh_kem_free(kem);
    return r;
}

int
ssh_kem_validate_public_key(const char *alg,
    const u_char *public_key, size_t public_key_len)
{
	struct sshkem *kem = NULL;
	size_t i, coeff_bytes;
	unsigned int c0, c1;
	int r = SSH_ERR_INVALID_FORMAT;

	if (alg == NULL || public_key == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((kem = ssh_kem_new(alg)) == NULL)
		return SSH_ERR_INVALID_ARGUMENT;

	/* FIPS 203 Section 7.2: encapsulation key type check. */
	if (public_key_len != ssh_kem_public_key_len(kem) ||
	    public_key_len < 32)
		goto out;

	/*
	 * The final 32 bytes contain rho. The preceding bytes
	 * encode pairs of 12-bit polynomial coefficients.
	 */
	coeff_bytes = public_key_len - 32;
	if (coeff_bytes % 3 != 0)
		goto out;

	/*
	 * FIPS 203 Section 7.2: modulus check.
	 * Both coefficients must be in [0, 3328].
	 */
	for (i = 0; i < coeff_bytes; i += 3) {
		c0 = (unsigned int)public_key[i] |
		    (((unsigned int)public_key[i + 1] & 0x0fU) << 8);
		c1 = ((unsigned int)public_key[i + 1] >> 4) |
		    ((unsigned int)public_key[i + 2] << 4);

		if (c0 >= 3329U || c1 >= 3329U)
			goto out;
	}

	r = 0;

out:
	ssh_kem_free(kem);
	return r;
}

int
ssh_kem_name_equal(const char *left, const char *right)
{
	const char *left_normalized, *right_normalized;

	left_normalized = ssh_kem_normalize_name(left);
	right_normalized = ssh_kem_normalize_name(right);
	if (left_normalized == NULL || right_normalized == NULL)
		return 0;
	return strcmp(left_normalized, right_normalized) == 0;
}

int
ssh_kem_response_digest(const char *name)
{
	if (ssh_kem_normalize_name(name) == NULL)
		return -1;
	return SSH_DIGEST_SHA256;
}

size_t
ssh_kem_response_len(const char *name)
{
	int digest_alg;

	if ((digest_alg = ssh_kem_response_digest(name)) == -1)
		return 0;
	return ssh_hmac_bytes(digest_alg);
}

static struct sshkem *
ssh_kem_from_name(const char *name)
{
	struct sshkem *kem;

	if (name == NULL)
		return NULL;
	kem = xcalloc(1, sizeof(*kem));
	if (strcmp(name, SSH_KEM_ALG_MLKEM512) == 0)
		kem->oqs = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
	else if (strcmp(name, SSH_KEM_DEFAULT_ALG) == 0)
		kem->oqs = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
	else if (strcmp(name, SSH_KEM_ALG_MLKEM1024) == 0)
		kem->oqs = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
	if (kem->oqs == NULL) {
		free(kem);
		return NULL;
	}
	kem->name = name;
	return kem;
}

struct sshkem *
ssh_kem_new(const char *name)
{
	return ssh_kem_from_name(ssh_kem_normalize_name(name));
}

void
ssh_kem_free(struct sshkem *kem)
{
	if (kem == NULL)
		return;
	OQS_KEM_free(kem->oqs);
	free(kem);
}

size_t
ssh_kem_public_key_len(struct sshkem *kem)
{
	return kem != NULL && kem->oqs != NULL ? kem->oqs->length_public_key : 0;
}

size_t
ssh_kem_secret_key_len(struct sshkem *kem)
{
	return kem != NULL && kem->oqs != NULL ? kem->oqs->length_secret_key : 0;
}

size_t
ssh_kem_ciphertext_len(struct sshkem *kem)
{
	return kem != NULL && kem->oqs != NULL ? kem->oqs->length_ciphertext : 0;
}

size_t
ssh_kem_shared_secret_len(struct sshkem *kem)
{
	return kem != NULL && kem->oqs != NULL ? kem->oqs->length_shared_secret : 0;
}

int
ssh_kem_keypair(struct sshkem *kem, u_char *public_key, u_char *secret_key)
{
	if (kem == NULL || kem->oqs == NULL || public_key == NULL ||
	    secret_key == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	return OQS_KEM_keypair(kem->oqs, public_key, secret_key) == OQS_SUCCESS ?
	    0 : SSH_ERR_LIBCRYPTO_ERROR;
}

int
ssh_kem_encaps(struct sshkem *kem, u_char *ciphertext,
    u_char *shared_secret, const u_char *public_key)
{
	if (kem == NULL || kem->oqs == NULL || ciphertext == NULL ||
	    shared_secret == NULL || public_key == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	return OQS_KEM_encaps(kem->oqs, ciphertext, shared_secret,
	    public_key) == OQS_SUCCESS ? 0 : SSH_ERR_LIBCRYPTO_ERROR;
}

int
ssh_kem_decaps(struct sshkem *kem, u_char *shared_secret,
    const u_char *ciphertext, const u_char *secret_key)
{
	if (kem == NULL || kem->oqs == NULL || shared_secret == NULL ||
	    ciphertext == NULL || secret_key == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	return OQS_KEM_decaps(kem->oqs, shared_secret, ciphertext,
	    secret_key) == OQS_SUCCESS ? 0 : SSH_ERR_LIBCRYPTO_ERROR;
}

int
ssh_kem_name_permitted(const char *allowlist, const char *name)
{
	char *cp, *list, *item;
	const char *normalized;
	int allowed = 0;

	if ((normalized = ssh_kem_normalize_name(name)) == NULL ||
	    allowlist == NULL)
		return 0;
	list = xstrdup(allowlist);
	for (cp = list; (item = strsep(&cp, ",")) != NULL;) {
		const char *candidate;

		if ((candidate = ssh_kem_normalize_name(item)) == NULL)
			continue;
		if (strcmp(candidate, normalized) == 0) {
			allowed = 1;
			break;
		}
	}
	free(list);
	return allowed;
}

int
ssh_kem_names_valid(const char *names)
{
	char *cp, *list, *item;
	int ret = 0;

	if (names == NULL || *names == '\0')
		return 0;
	list = xstrdup(names);
	for (cp = list; (item = strsep(&cp, ",")) != NULL;) {
		if (ssh_kem_normalize_name(item) == NULL)
			goto out;
	}
	ret = 1;
out:
	free(list);
	return ret;
}

int
ssh_kem_b64_encode(const u_char *data, size_t len, char **out)
{
	size_t outlen;
	char *encoded;
	int n;

	if (out != NULL)
		*out = NULL;
	if (data == NULL || out == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	outlen = ((len + 2) / 3) * 4 + 1;
	encoded = xcalloc(outlen, sizeof(*encoded));
	if ((n = b64_ntop(data, len, encoded, outlen)) == -1) {
		free(encoded);
		return SSH_ERR_INVALID_FORMAT;
	}
	encoded[n] = '\0';
	*out = encoded;
	return 0;
}

int
ssh_kem_b64_decode(const char *input, u_char **data, size_t *len)
{
	size_t maxlen;
	u_char *decoded;
	int n;

	if (data != NULL)
		*data = NULL;
	if (len != NULL)
		*len = 0;
	if (input == NULL || data == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	maxlen = strlen(input) * 3 / 4 + 4;
	decoded = xcalloc(maxlen, sizeof(*decoded));
	if ((n = b64_pton(input, decoded, maxlen)) == -1) {
		free(decoded);
		return SSH_ERR_INVALID_FORMAT;
	}
	*data = decoded;
	if (len != NULL)
		*len = (size_t)n;
	return 0;
}

static int
ssh_kem_identity_validate(struct ssh_kem_identity *identity)
{
	struct sshkem *kem;
	int ret = SSH_ERR_INVALID_FORMAT;

	if (identity == NULL || identity->alg == NULL ||
	    identity->public_key == NULL || identity->secret_key == NULL)
		return SSH_ERR_INVALID_FORMAT;
	if ((kem = ssh_kem_new(identity->alg)) == NULL)
		return SSH_ERR_INVALID_FORMAT;
	if (identity->public_key_len != ssh_kem_public_key_len(kem) ||
	    identity->secret_key_len != ssh_kem_secret_key_len(kem))
		goto out;
	ret = 0;
out:
	ssh_kem_free(kem);
	return ret;
}

int
ssh_kem_load_identity(const char *path, struct ssh_kem_identity **idp)
{
	FILE *f = NULL;
	char *line = NULL, *cp, *key, *value;
	size_t linesize = 0;
	struct ssh_kem_identity *identity = NULL;
	int ret = SSH_ERR_INVALID_FORMAT;

	if (idp != NULL)
		*idp = NULL;
	if (path == NULL || idp == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((f = fopen(path, "r")) == NULL)
		return SSH_ERR_SYSTEM_ERROR;
	identity = xcalloc(1, sizeof(*identity));
	while (getline(&line, &linesize, f) != -1) {
		cp = line;
		while (isspace((u_char)*cp))
			cp++;
		if (*cp == '\0' || *cp == '#' || *cp == '\n')
			continue;
		key = strsep(&cp, " \t=\r\n");
		if (key == NULL || cp == NULL)
			goto out;
		while (isspace((u_char)*cp) || *cp == '=')
			cp++;
		ssh_kem_trim(cp);
		value = cp;
		if (*value == '\0')
			goto out;
		if (strcasecmp(key, "algorithm") == 0) {
			const char *normalized;

			if ((normalized = ssh_kem_normalize_name(value)) == NULL)
				goto out;
			free(identity->alg);
			identity->alg = xstrdup(normalized);
		} else if (strcasecmp(key, "public") == 0) {
			free(identity->public_key);
			identity->public_key = NULL;
			identity->public_key_len = 0;
			if ((ret = ssh_kem_b64_decode(value, &identity->public_key,
			    &identity->public_key_len)) != 0)
				goto out;
		} else if (strcasecmp(key, "secret") == 0) {
			freezero(identity->secret_key, identity->secret_key_len);
			identity->secret_key = NULL;
			identity->secret_key_len = 0;
			if ((ret = ssh_kem_b64_decode(value, &identity->secret_key,
			    &identity->secret_key_len)) != 0)
				goto out;
		}
	}
	if ((ret = ssh_kem_identity_validate(identity)) != 0)
		goto out;
	*idp = identity;
	identity = NULL;
	ret = 0;
out:
	if (f != NULL)
		fclose(f);
	free(line);
	ssh_kem_identity_free(identity);
	return ret;
}

void
ssh_kem_identity_free(struct ssh_kem_identity *identity)
{
	if (identity == NULL)
		return;
	free(identity->alg);
	free(identity->public_key);
	freezero(identity->secret_key, identity->secret_key_len);
	freezero(identity, sizeof(*identity));
}

const char *
ssh_kem_identity_alg(const struct ssh_kem_identity *identity)
{
	return identity != NULL ? identity->alg : NULL;
}

const u_char *
ssh_kem_identity_public_key(const struct ssh_kem_identity *identity,
    size_t *lenp)
{
	if (lenp != NULL)
		*lenp = identity != NULL ? identity->public_key_len : 0;
	return identity != NULL ? identity->public_key : NULL;
}

const u_char *
ssh_kem_identity_secret_key(const struct ssh_kem_identity *identity,
    size_t *lenp)
{
	if (lenp != NULL)
		*lenp = identity != NULL ? identity->secret_key_len : 0;
	return identity != NULL ? identity->secret_key : NULL;
}

int
ssh_kem_build_mac_input(const u_char *sid, size_t sid_len,
    const char *user, const char *service, const char *alg,
    const u_char *public_key_blob, size_t public_key_blob_len,
    const u_char *ciphertext, size_t ciphertext_len,
    struct sshbuf **inputp)
{
    struct sshbuf *ctx = NULL, *input = NULL;
    int r = SSH_ERR_INTERNAL_ERROR;

    if (inputp != NULL)
        *inputp = NULL;

    if (sid == NULL || sid_len == 0 ||
        user == NULL || service == NULL || alg == NULL ||
        public_key_blob == NULL || public_key_blob_len == 0 ||
        ciphertext == NULL || ciphertext_len == 0 ||
        inputp == NULL ||
        ssh_kem_normalize_name(alg) == NULL)
        return SSH_ERR_INVALID_ARGUMENT;

    if ((ctx = sshbuf_new()) == NULL ||
        (input = sshbuf_new()) == NULL) {
        r = SSH_ERR_ALLOC_FAIL;
        goto out;
    }

    /*
     * ctx: the exact authentication request, challenge,
     * and response message type specified by the draft.
     */
    if ((r = sshbuf_put_u8(ctx,
        SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
        (r = sshbuf_put_cstring(ctx, user)) != 0 ||
        (r = sshbuf_put_cstring(ctx, service)) != 0 ||
        (r = sshbuf_put_cstring(ctx,
        SSH_KEM_AUTH_METHOD)) != 0 ||
        (r = sshbuf_put_cstring(ctx, alg)) != 0 ||
        (r = sshbuf_put_string(ctx, public_key_blob,
        public_key_blob_len)) != 0 ||
        (r = sshbuf_put_u8(ctx,
        SSH2_MSG_USERAUTH_KEM_CHALLENGE)) != 0 ||
        (r = sshbuf_put_cstring(ctx, alg)) != 0 ||
        (r = sshbuf_put_string(ctx, public_key_blob,
        public_key_blob_len)) != 0 ||
        (r = sshbuf_put_string(ctx, ciphertext,
        ciphertext_len)) != 0 ||
        (r = sshbuf_put_u8(ctx,
        SSH2_MSG_USERAUTH_KEM_RESPONSE)) != 0)
        goto out;

    /*
     * MAC_input = label || SSH_string(sid) || ctx.
     * The label is raw ASCII, without a length prefix.
     */
    if ((r = sshbuf_put(input,
        SSH_KEM_CLIENT_AUTH_LABEL,
        strlen(SSH_KEM_CLIENT_AUTH_LABEL))) != 0 ||
        (r = sshbuf_put_string(input, sid, sid_len)) != 0 ||
        (r = sshbuf_putb(input, ctx)) != 0)
        goto out;

    *inputp = input;
    input = NULL;
    r = 0;

out:
    sshbuf_free(ctx);
    sshbuf_free(input);
    return r;
}

int
ssh_kem_compute_confirmation(const u_char *sid, size_t sid_len,
    const char *user, const char *service, const char *alg,
    const u_char *public_key_blob, size_t public_key_blob_len,
    const u_char *ciphertext, size_t ciphertext_len,
    const u_char *shared_secret, size_t shared_secret_len,
    u_char *ca, size_t ca_len)
{
    struct sshbuf *mac_input = NULL;
    struct ssh_hmac_ctx *hmac = NULL;
    size_t expected_len;
    int r;

    expected_len = ssh_hmac_bytes(SSH_DIGEST_SHA256);

    if (shared_secret == NULL || ca == NULL ||
        shared_secret_len != 32 ||
        ca_len != expected_len ||
        ssh_kem_response_digest(alg) != SSH_DIGEST_SHA256)
        return SSH_ERR_INVALID_ARGUMENT;

    if ((r = ssh_kem_build_mac_input(sid, sid_len,
        user, service, alg,
        public_key_blob, public_key_blob_len,
        ciphertext, ciphertext_len, &mac_input)) != 0)
        return r;

    if ((hmac = ssh_hmac_start(SSH_DIGEST_SHA256)) == NULL) {
        r = SSH_ERR_ALLOC_FAIL;
        goto out;
    }

    if ((r = ssh_hmac_init(hmac, shared_secret,
        shared_secret_len)) != 0 ||
        (r = ssh_hmac_update_buffer(hmac, mac_input)) != 0 ||
        (r = ssh_hmac_final(hmac, ca, ca_len)) != 0)
        goto out;

    r = 0;

out:
    ssh_hmac_free(hmac);
    sshbuf_free(mac_input);
    return r;
}

#ifdef KEM_TEST_INSTRUMENTATION
void
kem_test_inc_pending(void)
{
	debug("KEM_PENDING_INC");
}

void
kem_test_dec_pending(void)
{
	debug("KEM_PENDING_DEC");
}
#endif