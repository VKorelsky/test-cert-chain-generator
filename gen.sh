#!/bin/bash

ROOT_CA_DIR="./root_ca"
INT_CA_DIR="./intermediate_ca"
LEAF_DIR="./leaf"
OUTPUT_DIR="./out"
OUTPUT_KEYS_DIR=$OUTPUT_DIR"/keys"
OUTPUT_CERTS_PEM_DIR=$OUTPUT_DIR"/certs-pem"
OUTPUT_CERTS_DER_DIR=$OUTPUT_DIR"/certs-der"
OUTPUT_CRLS_DIR=$OUTPUT_DIR"/crls"
NOW="$(date -u +"%Y%m%d%H%M%SZ")"
GLOBAL_CA_FLAGS="-notext"
FLAGS_VALID_FOR_100_Y="-days 36500"
FLAGS_EXPIRED="-startdate 200801010000Z -enddate $NOW"

cleanup() {
	rm -rf ${OUTPUT_DIR:?}/*;
}

generateRootCert() {
	echo "generating fresh root ca";
	mkdir -p $OUTPUT_KEYS_DIR
	openssl ecparam -name secp384r1 -genkey -noout -out $OUTPUT_KEYS_DIR/root.key;
	openssl req -new -key $OUTPUT_KEYS_DIR/root.key -out $OUTPUT_DIR/root.csr -config $ROOT_CA_DIR/root_req.config;
	
	cp $ROOT_CA_DIR/ca.ext $OUTPUT_DIR/root.ext
	echo "crlDistributionPoints = URI:$2" >> $OUTPUT_DIR/root.ext
	mkdir -p $OUTPUT_CERTS_PEM_DIR
	openssl ca -batch -in $OUTPUT_DIR/root.csr -out $OUTPUT_CERTS_PEM_DIR/root.pem -config $ROOT_CA_DIR/root.config -selfsign -extfile $OUTPUT_DIR/root.ext $1;
	rm -f $OUTPUT_DIR/root.ext;
	rm -f $OUTPUT_DIR/root.csr;
	
	mkdir -p $OUTPUT_CERTS_DER_DIR
	openssl x509 -inform PEM -outform DER -text -in $OUTPUT_CERTS_PEM_DIR/root.pem -out $OUTPUT_CERTS_DER_DIR/root.der;
}

generateIntermediateCert(){ 
	echo "generating fresh intermediate ca"; 
	openssl ecparam -name prime256v1 -genkey -noout -out $OUTPUT_KEYS_DIR/intermediate.key;
	openssl req -new -key $OUTPUT_KEYS_DIR/intermediate.key -out $OUTPUT_DIR/intermediate.csr -config $INT_CA_DIR/intermediate_req.config;

	cp $ROOT_CA_DIR/ca.ext $OUTPUT_DIR/root.ext
	echo "crlDistributionPoints = URI:$2" >> $OUTPUT_DIR/root.ext
	openssl ca -batch -in $OUTPUT_DIR/intermediate.csr -out $OUTPUT_CERTS_PEM_DIR/intermediate.pem -config $ROOT_CA_DIR/root.config -extfile $OUTPUT_DIR/root.ext $1;
	rm -f $OUTPUT_DIR/root.ext;
	rm -f $OUTPUT_DIR/intermediate.csr;
	
	openssl x509 -inform PEM -outform DER -text -in $OUTPUT_CERTS_PEM_DIR/intermediate.pem -out $OUTPUT_CERTS_DER_DIR/intermediate.der;
}

generateLeafCert(){
	echo "generating fresh leaf";
	openssl ecparam -name prime256v1 -genkey -noout -out $OUTPUT_KEYS_DIR/leaf.key;
	openssl req -new -key $OUTPUT_KEYS_DIR/leaf.key -out $OUTPUT_DIR/leaf.csr -config $LEAF_DIR/leaf_req.config;

	cp $LEAF_DIR/$2 $OUTPUT_DIR/leaf.ext
	echo "crlDistributionPoints = URI:$3" >> $OUTPUT_DIR/leaf.ext
	openssl ca -batch -in $OUTPUT_DIR/leaf.csr -out $OUTPUT_CERTS_PEM_DIR/leaf.pem -config $INT_CA_DIR/intermediate.config -extfile $OUTPUT_DIR/leaf.ext -extensions v3_req $1;
	rm -f $OUTPUT_DIR/leaf.ext;
	rm -f $OUTPUT_DIR/leaf.csr;
	
	openssl x509 -inform PEM -outform DER -text -in $OUTPUT_CERTS_PEM_DIR/leaf.pem -out $OUTPUT_CERTS_DER_DIR/leaf.der;
	# convert private key to newer pem format https://github.com/auth0/java-jwt/issues/272
	openssl pkcs8 -topk8 -inform pem -in $OUTPUT_KEYS_DIR/leaf.key -outform pem -nocrypt -out $OUTPUT_KEYS_DIR/leaf_private_key.pem
}

copyCertificatesAndGenerateCrls(){
	mkdir -p $1; 
	cp $OUTPUT_CERTS_PEM_DIR/root.pem $1/root.pem;
	cp $OUTPUT_CERTS_PEM_DIR/intermediate.pem $1/intermediate.pem;
	cp $OUTPUT_CERTS_PEM_DIR/leaf.pem $1/$2;
	mkdir -p $1/crls; 
	openssl ca -config $ROOT_CA_DIR/root.config -gencrl -out $1/crls/root.crl.pem;
	openssl ca -config $INT_CA_DIR/intermediate.config -gencrl -out $1/crls/intermediate.crl.pem;
}

generateChain(){
	[ $2 == "expire-root" ] && rootFlags="$FLAGS_EXPIRED" || rootFlags="$FLAGS_VALID_FOR_100_Y";
	generateRootCert "$rootFlags $GLOBAL_CA_FLAGS" "http://localhost:8007/$1/crls/root.crl.pem";
	
	[ $2 == "expire-intermediate" ] && intermediateFlags="$FLAGS_EXPIRED" || intermediateFlags="$FLAGS_VALID_FOR_100_Y";
	generateIntermediateCert "$intermediateFlags $GLOBAL_CA_FLAGS" "http://localhost:8007/$1/crls/root.crl.pem";
	
	[ $2 == "expire-leaf" ] && leafFlags="$FLAGS_EXPIRED" || leafFlags="$FLAGS_VALID_FOR_100_Y";
	generateLeafCert "$leafFlags $GLOBAL_CA_FLAGS" leaf_ext.config "http://localhost:8007/$1/crls/intermediate.crl.pem";
	
	if [ $3 == "revoke-intermediate" ]
  then
    echo "Revoking intermediate certificate"
    openssl ca -config $ROOT_CA_DIR/root.config -revoke $OUTPUT_CERTS_PEM_DIR/intermediate.pem
	elif [ $3 == "revoke-leaf" ]
  then
    echo "Revoking leaf certificate"
    openssl ca -config $INT_CA_DIR/intermediate.config -revoke $OUTPUT_CERTS_PEM_DIR/leaf.pem
	else
    echo "Not revoking certificates"
  fi

	copyCertificatesAndGenerateCrls "$TEST_OUTPUT_DIR/$1" "${4:-leaf.pem}";
}

generateLeaf(){
	[ $3 == "expire-leaf" ] && leafFlags="$FLAGS_EXPIRED" || leafFlags="$FLAGS_VALID_FOR_100_Y";
	generateLeafCert "$leafFlags $GLOBAL_CA_FLAGS" $4 "http://localhost:8007/$1/crls/intermediate.crl.pem";
	cp $OUTPUT_CERTS_PEM_DIR/leaf.pem "$TEST_OUTPUT_DIR/$1/$2";
}

generateChainValidationTestCertificates(){
	TEST_OUTPUT_DIR="./out/chain-validation-test"
	mkdir -p $TEST_OUTPUT_DIR; 

	echo "generating certificates for testing certificate validation";
  
	generateChain "root_expired" "expire-root" "revoke-none";
  generateChain "root_unrelated" "expire-none" "revoke-none";
  generateChain "intermediate_expired" "expire-intermediate" "revoke-none";
  generateChain "intermediate_revoked" "expire-none" "revoke-intermediate";
  generateChain "valid_chain" "expire-none" "revoke-leaf" "leaf_revoked.pem";
  
	generateLeaf "valid_chain" "leaf.pem" "expire-none" leaf_ext.config; 
	generateLeaf "valid_chain" "leaf_expired.pem" "expire-leaf" leaf_ext.config; 
	generateLeaf "valid_chain" "leaf_without_oid.pem" "expire-none" leaf_ext_no_oid.config; 
	generateLeaf "valid_chain" "leaf_with_non_critical_oid.pem" "expire-none" leaf_ext_non_crit_oid.config; 
}

execute() {
	cleanup;
	generateChainValidationTestCertificates;
}

execute

