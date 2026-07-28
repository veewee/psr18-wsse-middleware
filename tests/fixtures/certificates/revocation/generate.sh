#!/usr/bin/env bash
#
# Regenerates the revocation fixtures. Run from this directory: ./generate.sh
#
# These are generated with the openssl CLI on purpose. Production only ever *reads* a CRL, so the fixtures must
# come from a real CA's encoder rather than from the same library that parses them — phpseclib's CRL writer is
# also unreliable (revoke() before a load yields an empty list, and a freshly signed CRL carries no nextUpdate).
#
# Dates are pinned far out and the tests freeze the clock, so a fixture cannot age into a spurious failure.

set -euo pipefail
cd "$(dirname "$0")"

rm -f ./*.pem ./*.crt ./*.key ./index.txt* ./crlnumber* ./*.csr
: > index.txt
echo 1000 > crlnumber

cat > openssl.cnf <<'CNF'
[ ca ]
default_ca = CA_default

[ CA_default ]
dir            = .
database       = ./index.txt
crlnumber      = ./crlnumber
default_md     = sha256
# ~20 years, so the fixture does not expire during the life of the test suite.
default_crl_days = 7300

[ req ]
distinguished_name = dn
prompt             = no
x509_extensions    = v3_ca

# Passing -config replaces openssl's defaults, so the CA extensions have to be stated explicitly. Without
# basicConstraints CA:TRUE the chain check rejects the CA as "invalid CA certificate" and nothing verifies.
[ v3_ca ]
subjectKeyIdentifier = hash
basicConstraints     = critical,CA:TRUE
keyUsage             = critical,keyCertSign,cRLSign

# Deliberately multi-attribute: a CN-only name renders the same whichever order the components are joined in,
# which hides any RDN-ordering mismatch between the CRL issuer and the certificate issuer.
[ dn ]
C  = BE
O  = php-soap revocation
CN = WSSE Revocation CA
CNF

cat > other.cnf <<'CNF'
[ req ]
distinguished_name = dn
prompt             = no
x509_extensions    = v3_ca

[ v3_ca ]
subjectKeyIdentifier = hash
basicConstraints     = critical,CA:TRUE
keyUsage             = critical,keyCertSign,cRLSign

[ dn ]
C  = BE
O  = php-soap revocation
CN = WSSE Unrelated CA
CNF

# The CA that issues the leaf and signs the CRLs.
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt \
    -days 10950 -sha256 -config openssl.cnf 2>/dev/null

# The leaf, with a serial the tests assert on by value.
openssl req -new -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr \
    -subj "/C=BE/O=php-soap revocation/CN=WSSE Revocation Leaf" 2>/dev/null
openssl x509 -req -in leaf.csr -CA ca.crt -CAkey ca.key -set_serial 0x1234 \
    -days 10950 -sha256 -out leaf.crt 2>/dev/null

# A CRL from this CA that revokes nothing: the leaf must still verify against it.
openssl ca -config openssl.cnf -cert ca.crt -keyfile ca.key -gencrl -out crl-empty.pem 2>/dev/null

# The same CA's CRL after revoking the leaf.
openssl ca -config openssl.cnf -cert ca.crt -keyfile ca.key -revoke leaf.crt 2>/dev/null
openssl ca -config openssl.cnf -cert ca.crt -keyfile ca.key -gencrl -out crl-revoked.pem 2>/dev/null

# A short-lived CRL for the fail-closed-on-stale rule. It goes out of date a day after generation, and the test
# freezes the clock at a fixed instant (2036) that is past that nextUpdate but still well inside the leaf's
# validity — so staleness is what fires, not certificate expiry. Regenerating keeps that ordering intact.
openssl ca -config openssl.cnf -cert ca.crt -keyfile ca.key -gencrl -crldays 1 -out crl-short.pem 2>/dev/null

# No CRL is backdated to force staleness: older openssl rejects -startdate/-enddate on -gencrl, and the
# workarounds land a nextUpdate so close to now that the fixture flips state on its own. Pairing a short-lived
# CRL with a frozen clock keeps the outcome the same on every run.

# An impostor CA: the same subject name as the real one, a different key. Its CRL claims to speak for our
# issuer, so it passes the issuer-coverage check and is stopped only by the signature check. This is the forgery
# the "verify the list against an anchor" rule exists for — a forged empty list would otherwise un-revoke
# everything, and a forged populated one could revoke an honest signer.
openssl req -x509 -newkey rsa:2048 -nodes -keyout impostor-ca.key -out impostor-ca.crt \
    -days 10950 -sha256 -config openssl.cnf 2>/dev/null
: > impostor-index.txt
echo 3000 > impostor-crlnumber
sed -e 's#./index.txt#./impostor-index.txt#' -e 's#./crlnumber#./impostor-crlnumber#' \
    openssl.cnf > impostor.cnf
openssl ca -config impostor.cnf -cert impostor-ca.crt -keyfile impostor-ca.key -gencrl \
    -out crl-impostor.pem 2>/dev/null

# An unrelated CA and its CRL, to prove a CRL signed by someone else is not accepted as covering our issuer.
openssl req -x509 -newkey rsa:2048 -nodes -keyout other-ca.key -out other-ca.crt \
    -days 7300 -sha256 -config other.cnf 2>/dev/null
: > other-index.txt
echo 2000 > other-crlnumber
sed -e 's#./index.txt#./other-index.txt#' -e 's#./crlnumber#./other-crlnumber#' \
    -e 's/WSSE Revocation CA/WSSE Unrelated CA/' openssl.cnf > other-ca.cnf
openssl ca -config other-ca.cnf -cert other-ca.crt -keyfile other-ca.key -gencrl -out crl-other-ca.pem 2>/dev/null

rm -f leaf.csr leaf.key index.txt* crlnumber* other-index.txt* other-crlnumber* \
      impostor-index.txt* impostor-crlnumber* impostor.cnf impostor-ca.key impostor-ca.crt \
      openssl.cnf other.cnf other-ca.cnf other-ca.key

echo "Regenerated:"
ls -1 ./*.crt ./*.pem
