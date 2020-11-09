#!/bin/bash

ROOT_CA_DIR="./root_ca"
INT_CA_DIR="./intermediate_ca"
LEAF_DIR="./leaf"

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

	rm -f $ROOT_CA_DIR/root.csr;
}

generateIntermediateCert(){
	echo "generating fresh intermediate ca";
	openssl ecparam -name prime256v1 -genkey -noout -out $INT_CA_DIR/intermediate.key;
	openssl req -new -key $INT_CA_DIR/intermediate.key -out $INT_CA_DIR/intermediate.csr -config $INT_CA_DIR/intermediate_req.config;
	openssl ca -in $INT_CA_DIR/intermediate.csr -out $INT_CA_DIR/intermediate.pem -config $ROOT_CA_DIR/root.config -extfile $ROOT_CA_DIR/ca.ext -days 730;

	rm -f $INT_CA_DIR/intermediate.csr;
}

generateLeafCert(){
	echo "generating fresh leaf";
	openssl ecparam -name prime256v1 -genkey -noout -out $LEAF_DIR/leaf.key;
	openssl req -new -key $LEAF_DIR/leaf.key -out $LEAF_DIR/leaf.csr -config $LEAF_DIR/leaf_req.config;
	openssl ca -in $LEAF_DIR/leaf.csr -out $LEAF_DIR/leaf.pem -config $INT_CA_DIR/intermediate.config -days 365;
	# convert to newer pem format https://github.com/auth0/java-jwt/issues/270
	openssl pkcs8 -topk8 -inform pem -in $LEAF_DIR/leaf.key -outform pem -nocrypt -out $LEAF_DIR/leaf.pem

	rm -f $LEAF_DIR/leaf.csr;
}

execute() {
	cleanup;
	generateRootCert;
	generateIntermediateCert;
	generateLeafCert;
}

execute
