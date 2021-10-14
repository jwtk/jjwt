The RSA `*.key.pem` and `*.crt.pem` files in this directory were created for testing as follows:

    openssl req -x509 -newkey rsa:2048 -keyout rsa2048.key.pem -out rsa2048.crt.pem -days 365250 -nodes -subj '/C=US/ST=California/L=San Francisco/O=jsonwebtoken.io/OU=jjwt'
    openssl req -x509 -newkey rsa:3072 -keyout rsa3072.key.pem -out rsa3072.crt.pem -days 365250 -nodes -subj '/C=US/ST=California/L=San Francisco/O=jsonwebtoken.io/OU=jjwt'
    openssl req -x509 -newkey rsa:4096 -keyout rsa4096.key.pem -out rsa4096.crt.pem -days 365250 -nodes -subj '/C=US/ST=California/L=San Francisco/O=jsonwebtoken.io/OU=jjwt'

The only difference is the key size and file names using sizes of `2048`, `3072`, and `4096`.

The Elliptic Curve `*.key.pem` and `*.crt.pem` files in this directory were created for testing as follows:

    # prime256v1 is the ID that OpenSSL uses for secp256r1.  It uses the other secp* IDs as expected:
    openssl ecparam -name prime256v1 -genkey -noout -out ES256.key.pem
    openssl ecparam -name secp384r1 -genkey -noout -out ES384.key.pem
    openssl ecparam -name secp521r1 -genkey -noout -out ES512.key.pem
    
    openssl req -new -x509 -key ES256.key.pem -out ES256.crt.pem -days 365250 -nodes -subj '/C=US/ST=California/L=San Francisco/O=jsonwebtoken.io/OU=jjwt'
    openssl req -new -x509 -key ES384.key.pem -out ES384.crt.pem -days 365250 -nodes -subj '/C=US/ST=California/L=San Francisco/O=jsonwebtoken.io/OU=jjwt'
    openssl req -new -x509 -key ES512.key.pem -out ES512.crt.pem -days 365250 -nodes -subj '/C=US/ST=California/L=San Francisco/O=jsonwebtoken.io/OU=jjwt'
    
The above commands create a (non-password-protected) private key and a self-signed certificate for the associated key
size, valid for 1000 years.  These files are intended for testing purposes only and shouldn't be used in a production 
system.

All `ES*`, `RS*`, and `PS*` file prefixes are equal to JWA standard `SignatureAlgorithm` IDs.  This allows
easy file lookup based on the `SignatureAlgorithm` `getId()` value when authoring tests.

Finally, the `RS*` and `PS*` files in this directory are just are symlinks back to `rsa*` files based on the JWT alg 
names and their respective key sizes.  This is so the `RS*` and `PS*` algorithms can use the same files since there
is no difference in keys between the two sets of algorithms.
