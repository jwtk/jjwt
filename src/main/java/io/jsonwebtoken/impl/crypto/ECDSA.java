package io.jsonwebtoken.impl.crypto;


import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.lang.JOSEException;


/**
 * Elliptic Curve Digital Signature Algorithm (ECDSA) functions and utilities.
 */
public class ECDSA {


	/**
	 * Returns the expected signature byte array length (R + S parts) for
	 * the specified ECDSA algorithm.
	 *
	 * @param alg The ECDSA algorithm. Must be supported and not
	 *            {@code null}.
	 *
	 * @return The expected byte array length for the signature.
	 *
	 * @throws JOSEException If the algorithm is not supported.
	 */
	public static int getSignatureByteArrayLength(final SignatureAlgorithm alg)
		throws JOSEException {

		switch (alg) {
			case ES256: return 64;
			case ES384: return 96;
			case ES512: return 132;
			default:
				throw new JOSEException("unsupported algorithm: " + alg.name());
		}
	}


	/**
	 * Transcodes the JCA ASN.1/DER-encoded signature into the concatenated
	 * R + S format expected by ECDSA JWS.
	 *
	 * @param derSignature The ASN1./DER-encoded. Must not be {@code null}.
	 * @param outputLength The expected length of the ECDSA JWS signature.
	 *
	 * @return The ECDSA JWS encoded signature.
	 *
	 * @throws JOSEException If the ASN.1/DER signature format is invalid.
	 */
	public static byte[] transcodeSignatureToConcat(final byte[] derSignature, int outputLength)
		throws JOSEException {

		if (derSignature.length < 8 || derSignature[0] != 48) {
			throw new JOSEException("Invalid  ECDSA signature format");
		}

		int offset;
		if (derSignature[1] > 0) {
			offset = 2;
		} else if (derSignature[1] == (byte) 0x81) {
			offset = 3;
		} else {
			throw new JOSEException("Invalid  ECDSA signature format");
		}

		byte rLength = derSignature[offset + 1];

		int i;
		for (i = rLength; (i > 0) && (derSignature[(offset + 2 + rLength) - i] == 0); i--) {
			// do nothing
		}

		byte sLength = derSignature[offset + 2 + rLength + 1];

		int j;
		for (j = sLength; (j > 0) && (derSignature[(offset + 2 + rLength + 2 + sLength) - j] == 0); j--) {
			// do nothing
		}

		int rawLen = Math.max(i, j);
		rawLen = Math.max(rawLen, outputLength / 2);

		if ((derSignature[offset - 1] & 0xff) != derSignature.length - offset
			|| (derSignature[offset - 1] & 0xff) != 2 + rLength + 2 + sLength
			|| derSignature[offset] != 2
			|| derSignature[offset + 2 + rLength] != 2) {
			throw new JOSEException("Invalid  ECDSA signature format");
		}

		final byte[] concatSignature = new byte[2 * rawLen];

		System.arraycopy(derSignature, (offset + 2 + rLength) - i, concatSignature, rawLen - i, i);
		System.arraycopy(derSignature, (offset + 2 + rLength + 2 + sLength) - j, concatSignature, 2 * rawLen - j, j);

		return concatSignature;
	}



	/**
	 * Transcodes the ECDSA JWS signature into ASN.1/DER format for use by
	 * the JCA verifier.
	 *
	 * @param jwsSignature The JWS signature, consisting of the
	 *                     concatenated R and S values. Must not be
	 *                     {@code null}.
	 *
	 * @return The ASN.1/DER encoded signature.
	 *
	 * @throws JOSEException If the ECDSA JWS signature format is invalid.
	 */
	public static byte[] transcodeSignatureToDER(byte[] jwsSignature)
		throws JOSEException {

		int rawLen = jwsSignature.length / 2;

		int i = rawLen;

		while((i > 0) && (jwsSignature[rawLen - i] == 0)) i--;

		int j = i;

		if (jwsSignature[rawLen - i] < 0) {
			j += 1;
		}

		int k = rawLen;

		while ((k > 0) && (jwsSignature[2 * rawLen - k] == 0)) k--;

		int l = k;

		if (jwsSignature[2 * rawLen - k] < 0) {
			l += 1;
		}

		int len = 2 + j + 2 + l;

		if (len > 255) {
			throw new JOSEException("Invalid ECDSA signature format");
		}

		int offset;

		final byte derSignature[];

		if (len < 128) {
			derSignature = new byte[2 + 2 + j + 2 + l];
			offset = 1;
		} else {
			derSignature = new byte[3 + 2 + j + 2 + l];
			derSignature[1] = (byte) 0x81;
			offset = 2;
		}

		derSignature[0] = 48;
		derSignature[offset++] = (byte) len;
		derSignature[offset++] = 2;
		derSignature[offset++] = (byte) j;

		System.arraycopy(jwsSignature, rawLen - i, derSignature, (offset + j) - i, i);

		offset += j;

		derSignature[offset++] = 2;
		derSignature[offset++] = (byte) l;

		System.arraycopy(jwsSignature, 2 * rawLen - k, derSignature, (offset + l) - k, k);

		return derSignature;
	}


	/**
	 * Prevents public instantiation.
	 */
	private ECDSA() {}
}
