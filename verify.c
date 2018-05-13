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

#include "common.h"

int main(int argc, char **argv)
{
	const char *cname = argc >= 2 ? argv[1] : "ca.crt";
	const char *pname = argc >= 3 ? argv[2] : "/bin/sash";
	const char *dname = argc >= 4 ? argv[3] : "outfile.der";
	gnutls_x509_trust_list_t tl;
	gnutls_pkcs7_t pkcs;
	int err;
	gnutls_datum_t temp;
	int sigs;
	int i;

	tl = build_tl(cname);
	if (tl == NULL) {
		return 1;
	}

	pkcs = read_pkcs7(pname);
	if (pkcs == NULL) {
		gnutls_x509_trust_list_deinit(tl, 1);
		return 1;
	}

	err = gnutls_pkcs7_print(pkcs, GNUTLS_CRT_PRINT_COMPACT, &temp);
	if (err < 0) {
		gnutls_perror(err);
	} else {
		printf("Data: %s\n", temp.data);
		gnutls_free(temp.data);
	}

	sigs = gnutls_pkcs7_get_signature_count(pkcs);
	if (sigs < 0) {
		gnutls_perror(sigs);
		gnutls_pkcs7_deinit(pkcs);
		gnutls_x509_trust_list_deinit(tl, 1);
		return 1;
	}

	err = read_file(dname, &temp);
	if (err < 0) {
		gnutls_perror(err);
		gnutls_pkcs7_deinit(pkcs);
		gnutls_x509_trust_list_deinit(tl, 1);
		return 1;
	}

	for (i = 0; i < sigs; i++) {
		err = gnutls_pkcs7_verify(pkcs, tl, NULL, 0, i, &temp, 0);
		if (err < 0) {
			gnutls_perror(err);
		} else {
			printf("Signature #%d verified\n", i);
		}
	}

	gnutls_free(temp.data);

	gnutls_pkcs7_deinit(pkcs);
	gnutls_x509_trust_list_deinit(tl, 1);

	return 0;
}
