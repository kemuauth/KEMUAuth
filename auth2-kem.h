#ifndef AUTH2_KEM_H
#define AUTH2_KEM_H

struct Authmethod;
struct ssh;

extern struct Authmethod method_kem;

void auth2_kem_stop(struct ssh *ssh);

#endif