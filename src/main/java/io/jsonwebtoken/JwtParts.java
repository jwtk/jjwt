package io.jsonwebtoken;

/**
 * Container class which contains encoded header, payload and signature parts of
 * the token.
 *
 * @since 0.8
 */
public class JwtParts {

	private String base64UrlEncodedHeader;
	private String base64UrlEncodedPayload;
	private String base64UrlEncodedSignature;

	/**
	 * Get Base64 URL encoded header.
	 * 
	 * @return Base64 URL encoded header as String.
	 */
	public String getBase64UrlEncodedHeader() {
		return base64UrlEncodedHeader;
	}

	/**
	 * Set Base64 URL encoded header.
	 * 
	 * @param base64UrlEncodedHeader
	 *            Base64 URL encoded header as String.
	 */
	public void setBase64UrlEncodedHeader(String base64UrlEncodedHeader) {
		this.base64UrlEncodedHeader = base64UrlEncodedHeader;
	}

	/**
	 * Get Base64 URL encoded payload.
	 * 
	 * @return Base64 URL encoded payload as String.
	 */
	public String getBase64UrlEncodedPayload() {
		return base64UrlEncodedPayload;
	}

	/**
	 * Set Base64 URL encoded payload.
	 * 
	 * @param base64UrlEncodedPayload
	 *            Base64 URL encoded payload as String.
	 */
	public void setBase64UrlEncodedPayload(String base64UrlEncodedPayload) {
		this.base64UrlEncodedPayload = base64UrlEncodedPayload;
	}

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
