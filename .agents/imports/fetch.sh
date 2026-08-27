#!/usr/bin/env bash
# Refills this directory with the third-party configuration samples the wsse-import-* skills were checked
# against. See README.md for what each one exercises. Needs an authenticated `gh` and `curl`.
#
# Overwrites, does not merge. Leaves drafts/ alone: those are written here, not downloaded.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
mkdir -p samples/wspolicy samples/metro samples/soapui samples/ibm drafts

note() { printf '\n== %s\n' "$1"; }

note 'apache/cxf: WS-SecurityPolicy'
CXF="https://raw.githubusercontent.com/apache/cxf/main/systests/ws-security/src/test/resources/org/apache/cxf/systest/ws"
for f in \
  parts/DoubleItParts.wsdl parts/signed-parts-policy.xml parts/signed-elements-policy.xml \
  parts/encrypted-parts-policy.xml parts/content-encrypted-elements-policy.xml parts/req-elements-policy.xml \
  parts/signed-attachments-policy.xml parts/encrypted-attachments-policy.xml parts/signed-addr-policy.xml \
  parts/multiple-encrypted-elements-policy.xml \
  swa/DoubleItSwa.wsdl \
  bindings/DoubleItBindings.wsdl bindings/encrypt-before-signing-policy.xml bindings/encrypt-sig-policy.xml \
  bindings/protect-tokens-policy.xml bindings/sig-conf-policy.xml bindings/ts-first-policy.xml \
  bindings/only-sign-policy.xml \
  tokens/DoubleItTokens.wsdl tokens/endorsing-x509-supp-token-policy.xml \
  tokens/signed-endorsing-x509-supp-token-policy.xml tokens/signed-encrypted-supp-token-policy.xml \
  tokens/x509-supp-token-policy.xml \
  x509/DoubleItX509Addressing.wsdl x509/end-supp-token-policy.xml x509/supp-token-pki-policy.xml \
  x509/clean-policy.xml \
  algsuite/DoubleItAlgSuite.wsdl wssc/DoubleItWSSC.wsdl mtom/DoubleItMtom.wsdl \
  coverage_checker/DoubleItCoverageChecker.wsdl policy/DoubleItPolicy.wsdl
do
  mkdir -p "samples/wspolicy/$(dirname "$f")"
  curl -sSf "$CXF/$f" -o "samples/wspolicy/$f" || echo "  MISSING $f"
done

note 'eclipse-ee4j/metro-wsit: Metro idioms'
METRO="https://raw.githubusercontent.com/eclipse-ee4j/metro-wsit/master"
curl -sSf "$METRO/wsit/samples/ws-security/src/secure_attachments/etc/service/PingService.wsdl" \
  -o samples/metro/etc_PingService.wsdl || echo '  MISSING secure_attachments PingService.wsdl'
for n in 1 2; do
  curl -sSf "$METRO/wsit/ws-sx/wssx-impl/src/test/resources/security/AsymmetricBindingAssertion$n.xml" \
    -o "samples/metro/resources_AsymmetricBindingAssertion$n.xml" || echo "  MISSING AsymmetricBindingAssertion$n.xml"
done

# gh contents API, for paths with spaces and for repos raw.githubusercontent serves awkwardly.
urlencode() { python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$1"; }
fetch_content() { # repo, ref, path, destination
  gh api "repos/$1/contents/$(urlencode "$3")?ref=$2" --jq '.content' | base64 -d > "$4"
}

note 'RUB-NDS/SOAP-Test-Webservices: SoapUI projects with real Signature and Encryption entries'
for n in Axis2-EncTSSign Axis2-Sign Axis2-Enc Metro-EncTSSign Metro-Sign CXF-Services WCF-1; do
  fetch_content RUB-NDS/SOAP-Test-Webservices master \
    "SoapUI Projects/${n}-soapui-project.xml" "samples/soapui/rubnds_${n}.xml" || echo "  MISSING $n"
done

note 'SmartBear: SoapUI projects with an empty wssContainer, kept as a counter-example'
for n in "WSTF SC002 Scenario" "WSTF SC003 Scenario"; do
  fetch_content SmartBear/soapui next \
    "soapui/src/wstf/${n}-soapui-project.xml" "samples/soapui/$(echo "$n" | tr ' ' '_')-soapui-project.xml" \
    || echo "  MISSING $n"
done
curl -sSf "https://raw.githubusercontent.com/PacktPublishing/SoapUI-Cookbook/master/Chapter7/4219OS_07_codes/chapter7/WSSecurityUsernameTimestamp-soapui-project.xml" \
  -o samples/soapui/WSSecurityUsernameTimestamp-soapui-project.xml || echo '  MISSING cookbook project'

note 'IBM/webspherelab: the shipped WebSphere policy-set library and the cell general bindings'
WASCELL="supplemental/exampledata/twas/collector/unpacked/f29061ea7da5/root/opt/IBM/WebSphere/AppServer/profiles/AppSrv01/config/cells/DefaultCell01"
for pair in \
  "PolicySets/WS-I RSP/PolicyTypes/WSSecurity/policy.xml|wasps_WS-I-RSP_policy.xml" \
  "PolicySets/Username WSSecurity default/PolicyTypes/WSSecurity/policy.xml|wasps_Username_policy.xml" \
  "PolicySets/LTPA WSSecurity default/PolicyTypes/WSSecurity/policy.xml|wasps_LTPA_policy.xml" \
  "PolicySets/Username SecureConversation/PolicyTypes/WSSecurity/policy.xml|wasps_UsernameSecureConv_policy.xml" \
  "PolicySets/TrustServiceSymmetricDefault/PolicyTypes/WSSecurity/policy.xml|wasps_TrustSymmetric_policy.xml" \
  "PolicySets/Username WSSecurity default/PolicyTypes/WSAddressing/policy.xml|wasps_Username_wsaddressing_policy.xml" \
  "PolicyTypes/WSSecurity/bindings.xml|wasps_general_bindings.xml"
do
  fetch_content IBM/webspherelab main "$WASCELL/${pair%%|*}" "samples/ibm/${pair##*|}" \
    || echo "  MISSING ${pair%%|*}"
done

note 'windup/windup-java-ee-tests: a JAX-RPC client extension descriptor carrying security config'
fetch_content windup/windup-java-ee-tests master \
  "example-websphere/example-websphere-war/src/main/webapp/WEB-INF/ibm-webservicesclient-ext.xmi" \
  samples/ibm/windup_ibm-webservicesclient-ext.xmi || echo '  MISSING windup xmi'

printf '\n%s sample files\n' "$(find samples -type f | wc -l | tr -d ' ')"
