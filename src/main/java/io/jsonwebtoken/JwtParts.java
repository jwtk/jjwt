package io.jsonwebtoken;

public class JwtParts {

	private String base64UrlEncodedHeader;
	private String base64UrlEncodedPayload;
	private String base64UrlEncodedDigest;

	public String getBase64UrlEncodedHeader() {
		return base64UrlEncodedHeader;
	}

	public void setBase64UrlEncodedHeader(String base64UrlEncodedHeader) {
		this.base64UrlEncodedHeader = base64UrlEncodedHeader;
	}

	public String getBase64UrlEncodedPayload() {
		return base64UrlEncodedPayload;
	}

	public void setBase64UrlEncodedPayload(String base64UrlEncodedPayload) {
		this.base64UrlEncodedPayload = base64UrlEncodedPayload;
	}

	public String getBase64UrlEncodedDigest() {
		return base64UrlEncodedDigest;
	}

	public void setBase64UrlEncodedDigest(String base64UrlEncodedDigest) {
		this.base64UrlEncodedDigest = base64UrlEncodedDigest;
	}

}
