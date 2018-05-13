#ifndef COMMON_H
#define COMMON_H

int read_file(const char *name, gnutls_datum_t *data);
int write_file(const char *name, const gnutls_datum_t *data);
gnutls_x509_crt_t read_certificate(const char *name);
gnutls_privkey_t read_privkey(const char *name);
gnutls_x509_trust_list_t build_tl(const char *name);
gnutls_pkcs7_t read_pkcs7(const char *name);

#endif
