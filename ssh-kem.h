#ifndef SSH_KEM_H
#define SSH_KEM_H

#include <sys/types.h>

struct sshkem;
struct ssh_kem_identity;
struct sshbuf;

/* SSH user authentication method */
#define SSH_KEM_AUTH_METHOD "publickey-kem"

/* Domain separation label */
#define SSH_KEM_CLIENT_AUTH_LABEL "ssh-publickey-kem-client-auth"

/* Authentication algorithm profiles */
#define SSH_KEM_DEFAULT_ALG "ssh-mlkem-768-hmac-sha256"
#define SSH_KEM_ALG_MLKEM512 "ssh-mlkem-512-hmac-sha256"
#define SSH_KEM_ALG_MLKEM1024 "ssh-mlkem-1024-hmac-sha256"

/* SSH public key format identifiers */
#define SSH_KEM_KEY_FORMAT_MLKEM512 "ssh-mlkem-512"
#define SSH_KEM_KEY_FORMAT_MLKEM768 "ssh-mlkem-768"
#define SSH_KEM_KEY_FORMAT_MLKEM1024 "ssh-mlkem-1024"

/* Map an authentication profile to its SSH public key format. */
const char *ssh_kem_public_key_format(const char *alg);

/* Encode a raw KEM public key as an SSH public key blob. */
int ssh_kem_encode_public_key_blob(const char *alg,
    const u_char *public_key, size_t public_key_len,
    struct sshbuf **blobp);

/* Decode and validate the structure of an SSH KEM public key blob. */
int ssh_kem_decode_public_key_blob(const char *alg,
    const u_char *blob, size_t blob_len,
    u_char **public_keyp, size_t *public_key_lenp);

/* Check an ML-KEM encapsulation key according to FIPS 203 Section 7.2. */
int ssh_kem_validate_public_key(const char *alg,
    const u_char *public_key, size_t public_key_len);

struct sshkem *ssh_kem_new(const char *name);
void ssh_kem_free(struct sshkem *kem);
size_t ssh_kem_public_key_len(struct sshkem *kem);
size_t ssh_kem_secret_key_len(struct sshkem *kem);
size_t ssh_kem_ciphertext_len(struct sshkem *kem);
size_t ssh_kem_shared_secret_len(struct sshkem *kem);
int ssh_kem_keypair(struct sshkem *kem, u_char *public_key,
    u_char *secret_key);
int ssh_kem_encaps(struct sshkem *kem, u_char *ciphertext,
    u_char *shared_secret, const u_char *public_key);
int ssh_kem_decaps(struct sshkem *kem, u_char *shared_secret,
    const u_char *ciphertext, const u_char *secret_key);
const char *ssh_kem_normalize_name(const char *name);
int ssh_kem_name_equal(const char *left, const char *right);
int ssh_kem_response_digest(const char *name);
size_t ssh_kem_response_len(const char *name);
int ssh_kem_names_valid(const char *names);
int ssh_kem_name_permitted(const char *allowlist, const char *name);
int ssh_kem_b64_encode(const u_char *data, size_t len, char **out);
int ssh_kem_b64_decode(const char *input, u_char **data, size_t *len);
int ssh_kem_load_identity(const char *path, struct ssh_kem_identity **idp);
void ssh_kem_identity_free(struct ssh_kem_identity *identity);
const char *ssh_kem_identity_alg(const struct ssh_kem_identity *identity);
const u_char *ssh_kem_identity_public_key(const struct ssh_kem_identity *identity,
    size_t *lenp);
const u_char *ssh_kem_identity_secret_key(const struct ssh_kem_identity *identity,
    size_t *lenp);

/* Build the exact MAC_input defined by the publickey-kem draft. */
int ssh_kem_build_mac_input(const u_char *sid, size_t sid_len,
    const char *user, const char *service, const char *alg,
    const u_char *public_key_blob, size_t public_key_blob_len,
    const u_char *ciphertext, size_t ciphertext_len,
    struct sshbuf **inputp);

/* Compute the ML-KEM profile's 32-octet confirmation value. */
int ssh_kem_compute_confirmation(const u_char *sid, size_t sid_len,
    const char *user, const char *service, const char *alg,
    const u_char *public_key_blob, size_t public_key_blob_len,
    const u_char *ciphertext, size_t ciphertext_len,
    const u_char *shared_secret, size_t shared_secret_len,
    u_char *ca, size_t ca_len);

#endif