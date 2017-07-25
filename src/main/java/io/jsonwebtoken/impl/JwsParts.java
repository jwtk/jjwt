package io.jsonwebtoken.impl;

/**
 * Container class which contains (base64 encoded) header, payload and signature parts of
 * the token.
 *
 * @since 0.8
 */
public class JwsParts extends JwtParts {

	private String base64UrlEncodedSignature;

	/**
	 * Get Base64 URL encoded signature.
	 * 
	 * @return Base64 URL encoded signature as String.
	 */
	public String getBase64UrlEncodedSignature() {
		return base64UrlEncodedSignature;
	}

	/**
	 * Set Base64 URL encoded signature.
	 * 
	 * @param base64UrlEncodedSignature
	 *            Base64 URL encoded signature as String.
	 */
	public void setBase64UrlEncodedSignature(String base64UrlEncodedSignature) {
		this.base64UrlEncodedSignature = base64UrlEncodedSignature;
	}

}
