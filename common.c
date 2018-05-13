#include <stdio.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>

#include "common.h"

unsigned char *_read_file_buf(const char *name, unsigned int *flen)
{
	unsigned char *buf;
	FILE *fin;
	off_t size;

	fin = fopen(name, "r");
	if (!fin) {
		perror("fopen");
		return NULL;
	}
	if (fseeko(fin, 0, SEEK_END) < 0) {
		perror("fseeko");
		fclose(fin);
		return NULL;
	}
	size = ftello(fin);
	if (size < 0) {
		perror("ftello");
		fclose(fin);
		return NULL;
	}
	if (fseeko(fin, 0, SEEK_SET) < 0) {
		perror("fseeko");
		fclose(fin);
		return NULL;
	}
	buf = gnutls_malloc(size);
	if (fread(buf, 1, size, fin) != size) {
		gnutls_free(buf);
		fclose(fin);
		return NULL;
	}
	fclose(fin);

	*flen = size;

	return buf;
}

int read_file(const char *name, gnutls_datum_t *data)
{
	data->data = _read_file_buf(name, &data->size);

	return (data->data == NULL) ? GNUTLS_E_FILE_ERROR : 0;
}

int write_file(const char *name, const gnutls_datum_t *data)
{
	FILE *f = fopen(name, "w");

	if (!f)
		return GNUTLS_E_FILE_ERROR;

	if (fwrite(data->data, 1, data->size, f) != data->size) {
		perror("fwrite");
		fclose(f);
		return GNUTLS_E_FILE_ERROR;
	}

	fclose(f);
	return 0;
}

gnutls_x509_crt_t read_certificate(const char *name)
{
	gnutls_datum_t data;
	gnutls_x509_crt_t crt;
	int err;

	err = read_file(name, &data);
	if (err < 0) {
		gnutls_perror(err);
		return NULL;
	}

	err = gnutls_x509_crt_init(&crt);
	if (err < 0) {
		gnutls_perror(err);
		gnutls_free(data.data);
		return NULL;
	}
	err = gnutls_x509_crt_import(crt, &data,
			GNUTLS_X509_FMT_DER);
	if (err < 0) {
		int err2;

		err2 = gnutls_x509_crt_import(crt, &data,
				GNUTLS_X509_FMT_PEM);
		if (err2 >= 0)
			err = err2;
	}
	if (err < 0) {
		gnutls_perror(err);
		gnutls_x509_crt_deinit(crt);
		gnutls_free(data.data);
		return NULL;
	}

	gnutls_free(data.data);

	return crt;
}

gnutls_privkey_t read_privkey(const char *name)
{
	gnutls_datum_t data;
	gnutls_privkey_t key;
	int err;

	err = read_file(name, &data);
	if (err < 0) {
		gnutls_perror(err);
		return NULL;
	}

	err = gnutls_privkey_init(&key);
	if (err < 0) {
		gnutls_perror(err);
		gnutls_free(data.data);
		return NULL;
	}
	err = gnutls_privkey_import_x509_raw(key, &data,
			GNUTLS_X509_FMT_DER,
			NULL, 0);
	if (err < 0) {
		int err2;

		err2 = gnutls_privkey_import_x509_raw(key, &data,
				GNUTLS_X509_FMT_PEM,
				NULL, 0);
		if (err2 >= 0)
			err = err2;
	}
	if (err < 0) {
		gnutls_perror(err);
		gnutls_privkey_deinit(key);
		gnutls_free(data.data);
		return NULL;
	}

	gnutls_free(data.data);

	return key;
}

gnutls_x509_trust_list_t build_tl(const char *name)
{
	gnutls_x509_trust_list_t tl;
	int err;

	err = gnutls_x509_trust_list_init(&tl, 0);
	if (err < 0) {
		gnutls_perror(err);
		return NULL;
	}

	err = gnutls_x509_trust_list_add_trust_file(tl, name, NULL, GNUTLS_X509_FMT_DER, 0, 0);
	if (err < 0) {
		int err2;

		err2 = gnutls_x509_trust_list_add_trust_file(tl, name, NULL, GNUTLS_X509_FMT_PEM, 0, 0);
		if (err2 >= 0)
			err = err2;
	}
	if (err < 0) {
		gnutls_perror(err);
		gnutls_x509_trust_list_deinit(tl, 1);
		return NULL;
	}

	return tl;
}

gnutls_pkcs7_t read_pkcs7(const char *name)
{
	gnutls_datum_t data;
	gnutls_pkcs7_t pkcs;
	int err;

	err = read_file(name, &data);
	if (err < 0) {
		gnutls_perror(err);
		return NULL;
	}

	err = gnutls_pkcs7_init(&pkcs);
	if (err < 0) {
		gnutls_perror(err);
		gnutls_free(data.data);
		return NULL;
	}
	err = gnutls_pkcs7_import(pkcs, &data,
			GNUTLS_X509_FMT_DER);
	if (err < 0) {
		int err2;

		err2 = gnutls_pkcs7_import(pkcs, &data,
				GNUTLS_X509_FMT_DER);
		if (err2 >= 0)
			err = err2;
	}
	if (err < 0) {
		gnutls_perror(err);
		gnutls_pkcs7_deinit(pkcs);
		gnutls_free(data.data);
		return NULL;
	}

	gnutls_free(data.data);

	return pkcs;
}
