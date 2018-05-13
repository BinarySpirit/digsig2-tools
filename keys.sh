#!/bin/sh

certtool --rsa --bits 2048 --hash sha256 --generate-privkey --outfile ca.key

cat > template.ca << EOF
cn=DigSig CA
ca
expiration_days = -1
cert_signing_key
EOF
certtool --load-privkey ca.key --outfile ca.crt --generate-self-signed --template template.ca

certtool --rsa --bits 2048 --hash sha256 --generate-privkey --outfile signcert.key
cat > template.signcert << EOF
cn=DigSig Signing Key
expiration_days = 0
signing_key
crl_signing_key
EOF
certtool --load-ca-privkey ca.key --load-ca-certificate ca.crt --load-privkey signcert.key --outfile signcert.crt --generate-certificate --template template.signcert

certtool --load-privkey signcert.key --load-certificate signcert.crt --p7-time --p7-detached-sign --outfile template.der --outder --infile template.signcert --p7-include-cert
certtool --p7-verify --load-ca-certificate ca.crt --infile template.der --inder --load-data template.signcert
