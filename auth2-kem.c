#include "includes.h"

#include <sys/types.h>

#include <string.h>

#ifdef WITH_OPENSSL
# include <openssl/dh.h>
#endif

#include "hostfile.h"
#include "xmalloc.h"
#include "auth.h"
#include "auth-options.h"
#include "auth2-kem.h"
#include "dispatch.h"
#include "kex.h"
#include "log.h"
#include "match.h"
#include "misc.h"
#include "compat.h"
#include "monitor_wrap.h"
#include "packet.h"
#include "servconf.h"
#include "sshbuf.h"
#include "ssh-kem.h"
#include "sshkey.h"
#include "ssh2.h"
#include "ssherr.h"

extern ServerOptions options;

struct kem_authctxt {
	char *packet_method;
	char *alg;
	u_char *public_key;
	size_t public_key_len;
	u_char *ciphertext;
	size_t ciphertext_len;
};

static void
kem_authctxt_free(struct kem_authctxt *ctx)
{
	if (ctx == NULL)
		return;
	free(ctx->packet_method);
	free(ctx->alg);
	free(ctx->public_key);
	free(ctx->ciphertext);
	freezero(ctx, sizeof(*ctx));
}

static int
verify_pubkey_for_kem_and(struct ssh *ssh, const char *method,
    const char *pkalg, const u_char *pkblob, size_t pkblob_len,
    const u_char *sig, size_t sig_len,
    const char *kem_alg, const u_char *kem_public_key, size_t kem_public_key_len)
{
	Authctxt *authctxt = ssh->authctxt;
	struct passwd *pw = authctxt->pw;
	struct sshbuf *b = NULL;
	struct sshkey *key = NULL;
	struct sshauthopt *authopts = NULL;
	struct sshkey_sig_details *sig_details = NULL;
	char *userstyle = NULL;
	int authenticated = 0, pktype, r;

	pktype = sshkey_type_from_name(pkalg);
	if (pktype == KEY_UNSPEC)
		goto out;
	if ((r = sshkey_from_blob(pkblob, pkblob_len, &key)) != 0 || key == NULL)
		goto out;
	if (key->type != pktype)
		goto out;
	if (auth2_key_already_used(authctxt, key))
		goto out;
	if (match_pattern_list(pkalg, options.pubkey_accepted_algos, 0) != 1)
		goto out;
	if ((r = sshkey_check_cert_sigtype(key, options.ca_sign_algorithms)) != 0)
		goto out;
	if ((r = sshkey_check_rsa_length(key, options.required_rsa_size)) != 0)
		goto out;
	if ((b = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0)
		fatal_fr(r, "put session id");
	xasprintf(&userstyle, "%s%s%s", authctxt->user,
	    authctxt->style ? ":" : "",
	    authctxt->style ? authctxt->style : "");
	if ((r = sshbuf_put_u8(b, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, userstyle)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
	    (r = sshbuf_put_cstring(b, method)) != 0 ||
	    (r = sshbuf_put_u8(b, 1)) != 0 ||
	    (r = sshbuf_put_cstring(b, pkalg)) != 0 ||
	    (r = sshbuf_put_string(b, pkblob, pkblob_len)) != 0 ||
	    (r = sshbuf_put_cstring(b, kem_alg)) != 0 ||
	    (r = sshbuf_put_string(b, kem_public_key, kem_public_key_len)) != 0)
		fatal_fr(r, "reconstruct %s packet", method);
	if (mm_user_key_allowed(ssh, pw, key, 1, &authopts) &&
	    sshkey_verify(key, sig, sig_len,
	    sshbuf_ptr(b), sshbuf_len(b),
	    pkalg, ssh->compat, &sig_details) == 0) {
		authenticated = 1;
	}
	auth2_record_key(authctxt, authenticated, key);
	if (authenticated == 1 && auth_activate_options(ssh, authopts) != 0)
		authenticated = 0;
out:
	sshbuf_free(b);
	sshauthopt_free(authopts);
	sshkey_free(key);
	sshkey_sig_details_free(sig_details);
	free(userstyle);
	return authenticated;
}

void
auth2_kem_stop(struct ssh *ssh)
{
	Authctxt *authctxt;

	if (ssh == NULL || (authctxt = ssh->authctxt) == NULL)
		return;
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_KEM_RESPONSE, NULL);
#ifdef KEM_TEST_INSTRUMENTATION
	if (authctxt->methoddata != NULL)
		kem_test_dec_pending();
#endif
	kem_authctxt_free(authctxt->methoddata);
	authctxt->methoddata = NULL;
}

static int
send_kem_challenge(struct ssh *ssh, struct kem_authctxt *ctx)
{
	const u_char *wire_ciphertext = ctx->ciphertext;
	size_t wire_ciphertext_len = ctx->ciphertext_len;
#ifdef KEM_TEST_MUTATION
	u_char *mutated_ciphertext = NULL;
	const char *mutation;
	size_t i, bit, nflips;
	struct timespec ts;
#endif
	int r;

#ifdef KEM_TEST_MUTATION
	mutation = getenv("KEM_MUTATION_TYPE");

	if (mutation != NULL && strcmp(mutation, "valid") != 0) {
		if (strcmp(mutation, "truncated") == 0) {
			if (ctx->ciphertext_len == 0) {
				error_f("cannot truncate empty KEM ciphertext");
				return SSH_ERR_INVALID_FORMAT;
			}
			wire_ciphertext_len = ctx->ciphertext_len - 1;
		} else if (strcmp(mutation, "extended") == 0) {
			mutated_ciphertext = xmalloc(ctx->ciphertext_len + 1);
			memcpy(mutated_ciphertext, ctx->ciphertext,
			    ctx->ciphertext_len);
			mutated_ciphertext[ctx->ciphertext_len] = 0;
			wire_ciphertext = mutated_ciphertext;
			wire_ciphertext_len = ctx->ciphertext_len + 1;
		} else {
			mutated_ciphertext = xmalloc(ctx->ciphertext_len);
			memcpy(mutated_ciphertext, ctx->ciphertext,
			    ctx->ciphertext_len);

			if (strcmp(mutation, "onebit") == 0) {
				if (ctx->ciphertext_len == 0) {
					free(mutated_ciphertext);
					return SSH_ERR_INVALID_FORMAT;
				}
				bit = arc4random_uniform(
				    (u_int32_t)(ctx->ciphertext_len * 8));
				mutated_ciphertext[bit / 8] ^=
				    (u_char)(1U << (bit % 8));
			} else if (strcmp(mutation, "multibit") == 0) {
				if (ctx->ciphertext_len == 0) {
					free(mutated_ciphertext);
					return SSH_ERR_INVALID_FORMAT;
				}
				nflips = (ctx->ciphertext_len * 8) / 100 + 1;
				for (i = 0; i < nflips; i++) {
					bit = arc4random_uniform(
					    (u_int32_t)
					    (ctx->ciphertext_len * 8));
					mutated_ciphertext[bit / 8] ^=
					    (u_char)(1U << (bit % 8));
				}
			} else if (strcmp(mutation, "random") == 0) {
				arc4random_buf(mutated_ciphertext,
				    ctx->ciphertext_len);
			} else if (strcmp(mutation, "allzero") == 0) {
				memset(mutated_ciphertext, 0,
				    ctx->ciphertext_len);
			} else if (strcmp(mutation, "allff") == 0) {
				memset(mutated_ciphertext, 0xff,
				    ctx->ciphertext_len);
			} else {
				error_f("unknown KEM ciphertext mutation: %s",
				    mutation);
				free(mutated_ciphertext);
				return SSH_ERR_INVALID_FORMAT;
			}

			wire_ciphertext = mutated_ciphertext;
		}
	}
#endif

	if ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_KEM_CHALLENGE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, ctx->alg)) != 0 ||
	    (r = sshpkt_put_string(ssh, ctx->public_key,
	    ctx->public_key_len)) != 0 ||
	    (r = sshpkt_put_string(ssh, wire_ciphertext,
	    wire_ciphertext_len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		goto out;

#ifdef KEM_TEST_MUTATION
	if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == 0)
		debug("KEM_CHALLENGE_EPOCH:%lld.%09ld",
		    (long long)ts.tv_sec, ts.tv_nsec);
#endif

	r = 0;

out:
#ifdef KEM_TEST_MUTATION
	free(mutated_ciphertext);
#endif
	return r;
}

static int
input_userauth_kem_response(int type, u_int32_t seq, struct ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	struct kem_authctxt *ctx = authctxt != NULL ? authctxt->methoddata : NULL;
	char *alg = NULL, *packet_method = NULL;
	size_t response_len = 0;
	u_char *response = NULL;
	int ok = 0, r;

#ifdef KEM_TEST_MUTATION
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == 0)
		debug("KEM_RESPONSE_EPOCH:%lld.%09ld",
		    (long long)ts.tv_sec, ts.tv_nsec);
#endif

	if (authctxt == NULL || ctx == NULL)
		fatal_f("missing authentication context");
	if ((r = sshpkt_get_string(ssh, &response, &response_len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		goto out;
	if ((r = mm_auth_kem_respond(response, response_len,
	    ctx->packet_method, &ok)) != 0)
		goto out;
	r = 0;
out:
	alg = ctx != NULL && ctx->alg != NULL ? xstrdup(ctx->alg) : NULL;
	packet_method = ctx != NULL && ctx->packet_method != NULL ?
	    xstrdup(ctx->packet_method) : NULL;
	freezero(response, response_len);
	authctxt->postponed = 0;
	if (alg == NULL)
		alg = xstrdup(SSH_KEM_AUTH_METHOD);
	if (packet_method == NULL)
		packet_method = xstrdup(SSH_KEM_AUTH_METHOD);
	auth2_kem_stop(ssh);
	userauth_finish(ssh, ok, packet_method, alg);
	free(packet_method);
	free(alg);
	return r;
}

static int
userauth_kem(struct ssh *ssh, const char *method)
{
	Authctxt *authctxt = ssh->authctxt;
	struct kem_authctxt *ctx = NULL;
	u_char *public_key = NULL;
	size_t public_key_len = 0;
	char *alg = NULL;
	int r;

	if ((r = sshpkt_get_cstring(ssh, &alg, NULL)) != 0 ||
	    (r = sshpkt_get_string(ssh, &public_key, &public_key_len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		free(alg);
		free(public_key);
		fatal_fr(r, "parse packet");
	}
	if (!options.kem_authentication || !authctxt->valid) {
		free(alg);
		free(public_key);
		return 0;
	}
	ctx = xcalloc(1, sizeof(*ctx));
	ctx->packet_method = xstrdup(method);
	ctx->alg = alg;
	alg = NULL;
	ctx->public_key = public_key;
	ctx->public_key_len = public_key_len;
	public_key = NULL;
	if ((r = mm_auth_kem_init(ctx->packet_method, ctx->alg,
	    ctx->public_key, ctx->public_key_len,
	    &ctx->ciphertext, &ctx->ciphertext_len)) != 0 ||
	    (r = send_kem_challenge(ssh, ctx)) != 0) {
		kem_authctxt_free(ctx);
		ctx = NULL;
		goto out;
	}
#ifdef KEM_TEST_INSTRUMENTATION
	kem_test_inc_pending();
#endif
	authctxt->methoddata = ctx;
	authctxt->postponed = 1;
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_KEM_RESPONSE,
	    &input_userauth_kem_response);
	r = 0;
out:
	free(alg);
	free(public_key);
	return 0;
}

static int
userauth_kem_and(struct ssh *ssh, const char *method)
{
	Authctxt *authctxt = ssh->authctxt;
	struct kem_authctxt *ctx = NULL;
	u_char have_sig = 0;
	u_char *pkblob = NULL, *sig = NULL, *kem_public_key = NULL;
	size_t pkblob_len = 0, sig_len = 0, kem_public_key_len = 0;
	char *pkalg = NULL, *kem_alg = NULL;
	int r;

	if ((r = sshpkt_get_u8(ssh, &have_sig)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &pkalg, NULL)) != 0 ||
	    (r = sshpkt_get_string(ssh, &pkblob, &pkblob_len)) != 0 ||
	    (r = sshpkt_get_string(ssh, &sig, &sig_len)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &kem_alg, NULL)) != 0 ||
	    (r = sshpkt_get_string(ssh, &kem_public_key,
	    &kem_public_key_len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		goto out;
	}
	if (!options.kem_authentication || !options.pubkey_authentication ||
	    !authctxt->valid || have_sig == 0) {
		goto out;
	}
	if (!ssh_kem_name_permitted(options.kem_auth_algorithms, kem_alg))
		goto out;
	if (!verify_pubkey_for_kem_and(ssh, method, pkalg,
	    pkblob, pkblob_len, sig, sig_len,
	    kem_alg, kem_public_key, kem_public_key_len))
		goto out;
	ctx = xcalloc(1, sizeof(*ctx));
	ctx->packet_method = xstrdup(method);
	ctx->alg = kem_alg;
	kem_alg = NULL;
	ctx->public_key = kem_public_key;
	ctx->public_key_len = kem_public_key_len;
	kem_public_key = NULL;
	if ((r = mm_auth_kem_init(ctx->packet_method, ctx->alg,
	    ctx->public_key, ctx->public_key_len,
	    &ctx->ciphertext, &ctx->ciphertext_len)) != 0 ||
	    (r = send_kem_challenge(ssh, ctx)) != 0) {
		kem_authctxt_free(ctx);
		ctx = NULL;
		goto out;
	}
#ifdef KEM_TEST_INSTRUMENTATION
	kem_test_inc_pending();
#endif
	authctxt->methoddata = ctx;
	authctxt->postponed = 1;
	ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_KEM_RESPONSE,
	    &input_userauth_kem_response);
	out:
	free(pkalg);
	free(pkblob);
	free(sig);
	free(kem_alg);
	free(kem_public_key);
	return 0;
}

Authmethod method_kem = {
	&methodcfg_kem,
	userauth_kem,
};

extern struct authmethod_cfg methodcfg_kem_and;

Authmethod method_kem_and = {
	&methodcfg_kem_and,
	userauth_kem_and,
};
