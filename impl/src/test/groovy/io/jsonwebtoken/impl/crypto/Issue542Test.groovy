package io.jsonwebtoken.impl.crypto

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.SignatureAlgorithm
import io.jsonwebtoken.security.SignatureAlgorithms
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.junit.Test

import java.nio.charset.StandardCharsets
import java.security.PrivateKey
import java.security.PublicKey

/**
 * Asserts backwards-compatibility for 0.10.8 and later per https://github.com/jwtk/jjwt/issues/542
 */
class Issue542Test {

    /**
     * The following 3 strings were generated using the 0.10.7 implementation by calling this
     * class's `main` method below.
     *
     * DO NOT UPDATE THESE VALUES.  THEIR EXACT VALUES IS WHAT GUARANTEES BACKWARDS-COMPATIBILITY.
     *
     * Changing the values could reflect newer implementation behavior which defeats the entire purpose of the test :)
     */
    private static String PS256_0_10_7 = 'eyJhbGciOiJQUzI1NiJ9.eyJpc3MiOiJqb2UifQ.kvOr6hW_Bg6AjH8wmJd7C6S6xow1UaL3xIRrsxrZIgNYN912mHU_-QX_vggaQLLYZLZMWSuqqY_byFgiJ6c0814uf4PhzlkUL6P4FAqKvRMuazN0FMxK-oSt37jKzbLLfLQ2aNZ6jOMoUGn1zreITcm4oVYoZs1c4p8d-OMXjvzwO2rPTSyqrzvrmFF-ufh0gAAA9W8aDeFNPIcm66BC_RK9nhSfJaBdFGzN1dgZKRx8S5DwKurlJkfG6uESGG4pvhlQRtn8dmY_1HHsvKIBQD02zy1KyB3EYXJRtVSIUWY0lhhe7-AoE2TwfYQRaS38ReIhGLFzUIjUDYbxlBljeg'
    private static String PS384_0_10_7 = 'eyJhbGciOiJQUzM4NCJ9.eyJpc3MiOiJqb2UifQ.mlPowjRz0cP5J-MmCoegKHYagOHZ_ArXOR91_u8jMdwmOfdfEQIcC6K5hAgQGSZQC_pQDA51RUoUHatsQgXtHlSDC_VP9ZxcPkOptWScOUMXriLH31bTcrg0YhlYL-A7TTHLMhbUrOCKqjpWjU-GxcnOkM86e0joZgJUL7CpHUtyCFRrxOXtuTvGr2m_LdS7I5OyZ4xEP4JRcsOgOnGq-m7e3WX7LTDKjggtVq3Nmdl4GISgJdM7GHHZOJHckUjgD-T3X6oHQanFdXZnjEl7nqo9KfN0skerI681fJ8mbjIlbf68pM6tJwJXI8fr1tF4pcAZxXR17ITCrocVSRC6NuWOVzh_XyyEVMEWmLqrRvc4zyRUfqlDbUhMn55Z54bJnU2Z_IzUi1o9ndy7ckISHQVhuYFKu789DjW1BV4PFFxC4heghK_Gw4h7El6MIMVdvM8oLRbrjlf6BYCRnCxuTA_y10IyB7s8eEuUC-D6JjVtXSvCRkRo7f8dWQTjFLs7'
    private static String PS512_0_10_7 = 'eyJhbGciOiJQUzUxMiJ9.eyJpc3MiOiJqb2UifQ.r6sisG-FVaMoIJacMSdYZLWFBVoT6bXmf3X3humLZqzoGfsRw3q9-wJ2oIiR4ua2L_mPnJqyPcjFWoXLUzw-URFSyQEAX_S2mWTBn7avCFsmJUh2fMkplG0ynbIHCqReRDl3moQGallbl-SYgArSRI2HbpVt05xsVbk3BmxB8N8buKbBPfUqwZMicRqNpHxoOc-IXaClc7y93gFNfGBMEwXn2nK_ZFXY03pMBL_MHVsJprPmtGfQw0ZZUv29zZbZTkRb6W6bRCi3jIP8sBMnYDqG3_Oyz9sF74IeOoD9sCpgAuRnrSAXhEb3tr1uBwyT__DOI1ZdT8QGFiRRNpUZDm7g4ub7njhXQ6ppkEY6kEKCCoxSq5sAh6EzZQgAfbpKNXy5VIu8s1nR-iJ8GDpeTcpLRhbX8havNzWjc-kSnU95_D5NFoaKfIjofKideVU46lUdCk-m7q8mOoFz8UEK1cXq3t7ay2jLG_sNvv7oZPe2TC4ovQGiQP0Mt446XBuIvyXSvygD3_ACpRSfpAqVoP7Ce98NkV2QCJxYNX1cZ4Zj4HrNoNWMx81TFoyU7RoUhj4tHcgBt_3_jbCO0OCejwswAFhwYRXP3jXeE2QhLaN1QJ7p97ly8WxjkBRac3I2WAeJhOM4CWhtgDmHAER9571MWp-7n4h4bnx9tXXfV7k'

    private static Map<SignatureAlgorithm, String> JWS_0_10_7_VALUES = [
            (SignatureAlgorithms.PS256): PS256_0_10_7,
            (SignatureAlgorithms.PS384): PS384_0_10_7,
            (SignatureAlgorithms.PS512): PS512_0_10_7
    ]

    private static JcaX509CertificateConverter X509_CERT_CONVERTER = new JcaX509CertificateConverter()
    private static JcaPEMKeyConverter PEM_KEY_CONVERTER = new JcaPEMKeyConverter()

    private static PEMParser getParser(String filename) {
        InputStream is = Issue542Test.class.getResourceAsStream(filename)
        return new PEMParser(new BufferedReader(new InputStreamReader(is, StandardCharsets.ISO_8859_1)))
    }

    private static PublicKey readTestPublicKey(SignatureAlgorithm alg) {
        PEMParser parser = getParser(alg.getName() + '.crt.pem')
        X509CertificateHolder holder = parser.readObject() as X509CertificateHolder
        try {
            return X509_CERT_CONVERTER.getCertificate(holder).getPublicKey()
        } finally {
            parser.close()
        }
    }

    private static PrivateKey readTestPrivateKey(SignatureAlgorithm alg) {
        PEMParser parser = getParser(alg.getName() + '.key.pem')
        PrivateKeyInfo info = parser.readObject() as PrivateKeyInfo
        try {
            return PEM_KEY_CONVERTER.getPrivateKey(info)
        } finally {
            parser.close()
        }
    }

    /**
     * Asserts backwards-compatibility for https://github.com/jwtk/jjwt/issues/542
     */
    @Test
    void testRsaSsaPssBackwardsCompatibility() {

        def algs = [SignatureAlgorithms.PS256, SignatureAlgorithms.PS384, SignatureAlgorithms.PS512]

        for (alg in algs) {
            PublicKey key = readTestPublicKey(alg)
            String jws = JWS_0_10_7_VALUES[alg]
            def token = Jwts.parser().setSigningKey(key).parseClaimsJws(jws)
            assert 'joe' == token.body.getIssuer()
        }
    }

    /**
     * Used to generate 0.10.7 strings.  DO NOT call this method and replace the values at the top of this
     * class.  This method implementation was retained only to demonstrate how they were created for future reference.
     */
    static void main(String[] args) {
        def algs = [SignatureAlgorithms.PS256, SignatureAlgorithms.PS384, SignatureAlgorithms.PS512]
        for (alg in algs) {
            PrivateKey privateKey = readTestPrivateKey(alg)
            String jws = Jwts.builder().setIssuer('joe').signWith(privateKey, alg).compact()
            println "private static String ${alg.name()}_0_10_7 = '$jws'"
        }
    }
}
