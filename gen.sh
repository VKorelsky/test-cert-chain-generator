#!/bin/bash

ROOT_CA_DIR="./root_ca"

generateRootCert() {
  openssl ecparam -name secp384r1 -genkey -noout -out $ROOT_CA_DIR/root.key;
  openssl req -new -key $ROOT_CA_DIR/root.key -out $ROOT_CA_DIR/root.csr -config $ROOT_CA_DIR/root_req.config;
  openssl ca -in $ROOT_CA_DIR/root.csr -out $ROOT_CA_DIR/root.pem -config $ROOT_CA_DIR/root.config -selfsign -extfile $ROOT_CA_DIR/ca.ext -days 1095;

  rm -f $ROOT_CA_DIR/root.csr;
}

generateIntermediateCert(){
  openssl ecparam -name prime256v1 -genkey -noout -out intermediate.key;
  openssl req -new -key intermediate.key -out intermediate.csr -config intermediate_req.config;
  openssl ca -in intermediate.csr -out intermediate.pem -config root.config -extfile ca.ext -days 730;

  rm -f intermediate.csr;
}

generateLeafCert(){
  openssl ecparam -name prime256v1 -genkey -noout -out leaf.key;
  openssl req -new -key leaf.key -out leaf.csr -config leaf_req.config;
  openssl ca -in leaf.csr -out leaf.pem -config intermediate.config -days 365;

  rm -f leaf.csr;
}

execute() {
  generateRootCert;
#  generateIntermediateCert;
#  generateLeafCert;
}

execute
