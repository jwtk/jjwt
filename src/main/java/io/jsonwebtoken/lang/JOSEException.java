package io.jsonwebtoken.lang;


/**
 * Javascript Object Signing and Encryption (JOSE) exception.
 */
public class JOSEException extends Exception {


	private static final long serialVersionUID = 1L;


	/**
	 * Creates a new JOSE exception with the specified message.
	 *
	 * @param message The exception message.
	 */
	public JOSEException(final String message) {

		super(message);
	}
}
