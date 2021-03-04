The `*.key.pem` and `*.crt.pem` files in this directory were created for testing as follows:

    openssl req -x509 -newkey rsa:2048 -keyout rsa2048.key.pem -out rsa2048.crt.pem -days 365250 -nodes -subj '/C=US/ST=California/L=San Francisco/O=jsonwebtoken.io/OU=jjwt'
    openssl req -x509 -newkey rsa:3072 -keyout rsa3072.key.pem -out rsa3072.crt.pem -days 365250 -nodes -subj '/C=US/ST=California/L=San Francisco/O=jsonwebtoken.io/OU=jjwt'
    openssl req -x509 -newkey rsa:4096 -keyout rsa4096.key.pem -out rsa4096.crt.pem -days 365250 -nodes -subj '/C=US/ST=California/L=San Francisco/O=jsonwebtoken.io/OU=jjwt'

The only difference is the key size and file names using sizes of `2048`, `3072`, and `4096`.
    
Each command creates a (non-password-protected) private key and a self-signed certificate for the associated key size, 
valid for 1000 years.  These files are intended for testing purposes only and shouldn't be used in a production system.

Finally, the `RS*` and `PS*` files in this directory are just are symlinks back to these files based on the JWT alg 
names and their respective key sizes.  This enables easy file lookup based on the `SignatureAlgorithm` `name()` value 
when authoring tests.
