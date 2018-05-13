/*
 * DigSig2-related tools
 *
 * Copyright 2018 Dmitry Eremin-Solenikov
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */
#include <stdio.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>

#include "common.h"

int main(int argc, char **argv)
{
	const char *cname = argc >= 2 ? argv[1] : "signcert.crt";
	const char *kname = argc >= 3 ? argv[2] : "signcert.key";
	const char *fname = argc >= 4 ? argv[3] : "/bin/sash";
	const char *oname = argc >= 5 ? argv[4] : "outfile.der";
	gnutls_x509_crt_t crt;
	gnutls_privkey_t key;
	gnutls_pkcs7_t pkcs;
	int err;
	gnutls_datum_t temp;

	crt = read_certificate(cname);
	if (crt == NULL) {
		return 1;
	}

	err = gnutls_x509_crt_get_dn2(crt, &temp);
	if (err < 0) {
		gnutls_perror(err);
	} else {
		fprintf(stdout, "Certificate DN: %s\n", temp.data);
		gnutls_free(temp.data);
	}

	key = read_privkey(kname);
	if (key == NULL) {
		gnutls_x509_crt_deinit(crt);
		return 1;
	}

	err = read_file(fname, &temp);
	if (err < 0) {
		gnutls_perror(err);
		gnutls_privkey_deinit(key);
		gnutls_x509_crt_deinit(crt);
		return 1;
	}

	err = gnutls_pkcs7_init(&pkcs);
	if (err < 0) {
		gnutls_perror(err);
		gnutls_free(temp.data);
		gnutls_privkey_deinit(key);
		gnutls_x509_crt_deinit(crt);
		return 1;
	}

	err = gnutls_pkcs7_sign(pkcs, crt, key, &temp, NULL, NULL, GNUTLS_DIG_SHA256, GNUTLS_PKCS7_INCLUDE_TIME | GNUTLS_PKCS7_INCLUDE_CERT);
	if (err < 0) {
		gnutls_perror(err);
		gnutls_free(temp.data);
		gnutls_pkcs7_deinit(pkcs);
		gnutls_privkey_deinit(key);
		gnutls_x509_crt_deinit(crt);
		return 1;
	}

	gnutls_free(temp.data);

	err = gnutls_pkcs7_export2(pkcs, GNUTLS_X509_FMT_DER, &temp);
	if (err < 0) {
		gnutls_perror(err);
		gnutls_pkcs7_deinit(pkcs);
		gnutls_privkey_deinit(key);
		gnutls_x509_crt_deinit(crt);
		return 1;
	}

	err = write_file(oname, &temp);
	if (err < 0) {
		gnutls_perror(err);
		gnutls_free(temp.data);
		gnutls_pkcs7_deinit(pkcs);
		gnutls_privkey_deinit(key);
		gnutls_x509_crt_deinit(crt);
		return 1;
	}

	gnutls_free(temp.data);
	gnutls_pkcs7_deinit(pkcs);
	gnutls_privkey_deinit(key);
	gnutls_x509_crt_deinit(crt);

	return 0;
}
