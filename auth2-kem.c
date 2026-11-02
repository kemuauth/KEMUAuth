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
	/* Privileged monitor holds an unconsumed challenge. */
	int monitor_pending;
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

void
auth2_kem_stop(struct ssh *ssh)
{
	Authctxt *authctxt;
	struct kem_authctxt *ctx;

	if (ssh == NULL || (authctxt = ssh->authctxt) == NULL)
		return;

	ssh_dispatch_set(ssh,
	    SSH2_MSG_USERAUTH_KEM_RESPONSE, NULL);

	ctx = authctxt->methoddata;

	/*
	 * A pending challenge must be cancelled before
	 * the local authentication context is released.
	 */
	if (ctx != NULL && ctx->monitor_pending) {
		mm_auth_kem_cancel();
		ctx->monitor_pending = 0;
	}

	kem_authctxt_free(authctxt->methoddata);
	authctxt->methoddata = NULL;
}

static int
send_kem_challenge(struct ssh *ssh, struct kem_authctxt *ctx)
{
	int r;

	if ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_KEM_CHALLENGE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, ctx->alg)) != 0 ||
	    (r = sshpkt_put_string(ssh, ctx->public_key,
	    ctx->public_key_len)) != 0 ||
	    (r = sshpkt_put_string(ssh, ctx->ciphertext,
	    ctx->ciphertext_len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		return r;

	return 0;
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

	if (authctxt == NULL || ctx == NULL)
		fatal_f("missing authentication context");
	if ((r = sshpkt_get_string(ssh, &response, &response_len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		goto out;
	r = mm_auth_kem_respond(response, response_len,
		ctx->packet_method, &ok);
	if (r != 0)
		goto out;

	/*
	* The monitor has consumed the challenge, regardless
	* of whether the confirmation value was accepted.
	*/
	ctx->monitor_pending = 0;
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
		&ctx->ciphertext, &ctx->ciphertext_len)) != 0) {
		kem_authctxt_free(ctx);
		ctx = NULL;
		goto out;
	}

	/* The monitor now owns an outstanding challenge. */
	ctx->monitor_pending = 1;

	if ((r = send_kem_challenge(ssh, ctx)) != 0) {
		/*
		* Challenge transmission failed. Cancel the
		* privileged state before releasing this context.
		*/
		mm_auth_kem_cancel();
		ctx->monitor_pending = 0;
		kem_authctxt_free(ctx);
		ctx = NULL;
		goto out;
	}
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

Authmethod method_kem = {
	&methodcfg_kem,
	userauth_kem,
};

