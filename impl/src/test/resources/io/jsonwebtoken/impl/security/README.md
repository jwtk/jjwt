The RSA `*.key.pem`, `*.crt.pem`, `*.pub.pem`, and `*.pkcs1.key.pem` files in this directory were created for testing
using the `openssl` version `3.1.2` as follows:

    openssl req -new -x509 -newkey rsa:2048 -keyout RS256.key.pem -out RS256.crt.pem -days 365250 -nodes -subj '/C=US/ST=California/L=San Francisco/O=jsonwebtoken.io/OU=jjwt'
    openssl req -new -x509 -newkey rsa:3072 -keyout RS384.key.pem -out RS384.crt.pem -days 365250 -nodes -subj '/C=US/ST=California/L=San Francisco/O=jsonwebtoken.io/OU=jjwt'
    openssl req -new -x509 -newkey rsa:4096 -keyout RS512.key.pem -out RS512.crt.pem -days 365250 -nodes -subj '/C=US/ST=California/L=San Francisco/O=jsonwebtoken.io/OU=jjwt'
    openssl req -new -x509 -newkey rsa-pss  -keyout PS256.key.pem -out PS256.crt.pem -days 365250 -nodes -subj '/C=US/ST=California/L=San Francisco/O=jsonwebtoken.io/OU=jjwt' -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_pss_keygen_md:sha256 -pkeyopt rsa_pss_keygen_mgf1_md:sha256 -pkeyopt rsa_pss_keygen_saltlen:32 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sigopt rsa_mgf1_md:sha256 -sha256
    openssl req -new -x509 -newkey rsa-pss  -keyout PS384.key.pem -out PS384.crt.pem -days 365250 -nodes -subj '/C=US/ST=California/L=San Francisco/O=jsonwebtoken.io/OU=jjwt' -pkeyopt rsa_keygen_bits:3072 -pkeyopt rsa_pss_keygen_md:sha384 -pkeyopt rsa_pss_keygen_mgf1_md:sha384 -pkeyopt rsa_pss_keygen_saltlen:48 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:48 -sigopt rsa_mgf1_md:sha384 -sha384
    openssl req -new -x509 -newkey rsa-pss  -keyout PS512.key.pem -out PS512.crt.pem -days 365250 -nodes -subj '/C=US/ST=California/L=San Francisco/O=jsonwebtoken.io/OU=jjwt' -pkeyopt rsa_keygen_bits:4096 -pkeyopt rsa_pss_keygen_md:sha512 -pkeyopt rsa_pss_keygen_mgf1_md:sha512 -pkeyopt rsa_pss_keygen_saltlen:64 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:64 -sigopt rsa_mgf1_md:sha512 -sha512

    # extract the public key from the X.509 certificates to their own files:
    openssl x509 -pubkey -noout -in RS256.crt.pem > RS256.pub.pem
    openssl x509 -pubkey -noout -in RS384.crt.pem > RS384.pub.pem
    openssl x509 -pubkey -noout -in RS512.crt.pem > RS512.pub.pem
    openssl x509 -pubkey -noout -in PS256.crt.pem > PS256.pub.pem
    openssl x509 -pubkey -noout -in PS384.crt.pem > PS384.pub.pem
    openssl x509 -pubkey -noout -in PS512.crt.pem > PS512.pub.pem
    
    # convert the PKCS8 private key format to PKCS1 format for additional testing:
    openssl rsa -in RS256.key.pem -traditional -out RS256.pkcs1.key.pem
    openssl rsa -in RS384.key.pem -traditional -out RS384.pkcs1.key.pem
    openssl rsa -in RS512.key.pem -traditional -out RS512.pkcs1.key.pem
    openssl rsa -in PS256.key.pem -traditional -out PS256.pkcs1.key.pem
    openssl rsa -in PS384.key.pem -traditional -out PS384.pkcs1.key.pem
    openssl rsa -in PS512.key.pem -traditional -out PS512.pkcs1.key.pem

The only difference is the key size and file names using sizes of `2048`, `3072`, and `4096`.

The Elliptic Curve `*.key.pem`, `*.crt.pem` and `*.pub.pem` files in this directory were created for testing as follows:

    # prime256v1 is the ID that OpenSSL uses for secp256r1.  It uses the other secp* IDs as expected:
    openssl ecparam -name prime256v1 -genkey -noout -out ES256.key.pem
    openssl ecparam -name secp384r1 -genkey -noout -out ES384.key.pem
    openssl ecparam -name secp521r1 -genkey -noout -out ES512.key.pem
    
    # generate X.509 Certificates containing the public key based on the private key:
    openssl req -new -x509 -key ES256.key.pem -out ES256.crt.pem -days 365250 -nodes -subj '/C=US/ST=California/L=San Francisco/O=jsonwebtoken.io/OU=jjwt'
    openssl req -new -x509 -key ES384.key.pem -out ES384.crt.pem -days 365250 -nodes -subj '/C=US/ST=California/L=San Francisco/O=jsonwebtoken.io/OU=jjwt'
    openssl req -new -x509 -key ES512.key.pem -out ES512.crt.pem -days 365250 -nodes -subj '/C=US/ST=California/L=San Francisco/O=jsonwebtoken.io/OU=jjwt'
    
    # extract the public key from the X.509 certificates to their own files:
    openssl x509 -pubkey -noout -in ES256.crt.pem > ES256.pub.pem
    openssl x509 -pubkey -noout -in ES384.crt.pem > ES384.pub.pem
    openssl x509 -pubkey -noout -in ES512.crt.pem > ES512.pub.pem
  
The Edwards Curve `*.key.pem`, `*.crt.pem` and `*.pub.pem` files in this directory were created for testing as follows.
Note that we don't/can't create self-signed certificates (`*.crt.pem` files) for X25519 and X448 because these 
algorithms cannot be used for signing (perhaps we could have signed them with another key, but it wasn't necessary
for our testing):

    # generate the private keys:
    openssl genpkey -algorithm Ed25519 -out Ed25519.key.pem
    openssl genpkey -algorithm X25519 -out X25519.key.pem
    openssl genpkey -algorithm Ed448 -out Ed448.key.pem
    openssl genpkey -algorithm X448 -out X448.key.pem

    # obtain the public key from the private key:
    openssl pkey -pubout -inform pem -outform pem -in X25519.key.pem -out X25519.pub.pem
    openssl pkey -pubout -inform pem -outform pem -in X448.key.pem -out X448.pub.pem
    openssl pkey -pubout -inform pem -outform pem -in Ed25519.key.pem -out Ed25519.pub.pem
    openssl pkey -pubout -inform pem -outform pem -in Ed448.key.pem -out Ed448.pub.pem
    
    # generate X.509 Certificates containing the public key based on the private key:
    openssl req -new -x509 -key Ed25519.key.pem -out Ed25519.crt.pem -days 365250 -nodes -subj '/C=US/ST=California/L=San Francisco/O=jsonwebtoken.io/OU=jjwt'
    openssl req -new -x509 -key Ed448.key.pem -out Ed448.crt.pem -days 365250 -nodes -subj '/C=US/ST=California/L=San Francisco/O=jsonwebtoken.io/OU=jjwt'
    # note that there are no self-signed certificates for X25519 and X448 because these algorithms can't be used for signing

The above commands create a (non-password-protected) private key and a self-signed certificate for the associated key
size, valid for 1000 years.  These files are intended for testing purposes only and shouldn't be used in a production 
system.

All `ES*`, `RS*`, `PS*`, `X*` and `Ed*` file prefixes are equal to JWA standard `SignatureAlgorithm` IDs or Edwards
Curve IDs.  This allows easy file lookup based on the `SignatureAlgorithm` `getId()` or `EdwardsCurve#getId()` value 
when authoring tests.

Finally, the `EdDSA*` files in this directory are just are symlinks back to source files based on 
the `EdSignatureAlgorithm`'s preferred `Ed448` key sizes.
