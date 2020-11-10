#!/bin/bash

ROOT_CA_DIR="./root_ca"
INT_CA_DIR="./intermediate_ca"
LEAF_DIR="./leaf"
OUTPUT_DIR="./out"

cleanup() {
	rm -f $ROOT_CA_DIR/root.key;
	rm -f $ROOT_CA_DIR/root.pem;

	rm -f $INT_CA_DIR/intermediate.key;
	rm -f $INT_CA_DIR/intermediate.pem;

	rm -f $LEAF_DIR/leaf.key;
	rm -f $LEAF_DIR/leaf.pem;
}

generateRootCert() {
	echo "generating fresh root ca";
	openssl ecparam -name secp384r1 -genkey -noout -out $ROOT_CA_DIR/root.key;
	openssl req -new -key $ROOT_CA_DIR/root.key -out $ROOT_CA_DIR/root.csr -config $ROOT_CA_DIR/root_req.config;
	openssl ca -in $ROOT_CA_DIR/root.csr -out $ROOT_CA_DIR/root.pem -config $ROOT_CA_DIR/root.config -selfsign -extfile $ROOT_CA_DIR/ca.ext -days 1095;
	openssl x509 -inform PEM -outform DER -text -in $ROOT_CA_DIR/root.pem -out $OUTPUT_DIR/root.der;
	openssl ca -config root_ca/root.config -gencrl -out root_ca/root.crl.pem

	rm -f $ROOT_CA_DIR/root.csr;
}
generateIntermediateCert(){ 
	echo "generating fresh intermediate ca"; 
	openssl ecparam -name prime256v1 -genkey -noout -out $INT_CA_DIR/intermediate.key;
	openssl req -new -key $INT_CA_DIR/intermediate.key -out $INT_CA_DIR/intermediate.csr -config $INT_CA_DIR/intermediate_req.config;
	openssl ca -in $INT_CA_DIR/intermediate.csr -out $INT_CA_DIR/intermediate.pem -config $ROOT_CA_DIR/root.config -extfile $ROOT_CA_DIR/ca.ext -days 730;
	openssl x509 -inform PEM -outform DER -text -in $INT_CA_DIR/intermediate.pem -out $OUTPUT_DIR/intermediate.der;
	openssl ca -config intermediate_ca/intermediate.config -gencrl -out intermediate_ca/intermediate.crl.pem

	rm -f $INT_CA_DIR/intermediate.csr;
}

generateLeafCert(){
	echo "generating fresh leaf";
	openssl ecparam -name prime256v1 -genkey -noout -out $LEAF_DIR/leaf.key;
	openssl req -new -key $LEAF_DIR/leaf.key -out $LEAF_DIR/leaf.csr -config $LEAF_DIR/leaf_req.config;
	openssl ca -in $LEAF_DIR/leaf.csr -out $LEAF_DIR/leaf.pem -config $INT_CA_DIR/intermediate.config -extfile $LEAF_DIR/leaf_req_ext.config -extensions v3_req -days 365;
	openssl x509 -inform PEM -outform DER -text -in $LEAF_DIR/leaf.pem -out $OUTPUT_DIR/leaf.der;
	# convert private key to newer pem format https://github.com/auth0/java-jwt/issues/272
	openssl pkcs8 -topk8 -inform pem -in $LEAF_DIR/leaf.key -outform pem -nocrypt -out $LEAF_DIR/leaf_private_key.pem


	rm -f $LEAF_DIR/leaf.csr;
}

execute() {
	cleanup;
	generateRootCert;
	generateIntermediateCert;
	generateLeafCert;
}

execute
