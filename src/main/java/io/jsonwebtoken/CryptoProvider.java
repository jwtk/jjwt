package io.jsonwebtoken;

import java.util.Map;

public interface CryptoProvider {
	/**
	 * 
	 * @param plain the string that needs to be signed
	 * @param config configuration hashmap that requires exclusive information required for sign
	 * 		This config map can be implementation specific as the user will have to implement the CryptoProvider and provide
	 * 		an instance for using jjwt.
	 * @return String the signed value as a String
	 * 
	 * Parsing of the config map is left for the implementation
	 */
	public String sign(String plain, Map<String, Object> config);
	
	/**
	 * 
	 * @param plain the string that has been signed
	 * @param sign the sign that is to be verified for the given plain text
	 * @param config configuration hashmap that requires exclusive information required for verify
	 *		This config map can be implementation specific as the user will have to implement the CryptoProvider and provide
	 * 		an instance for using jjwt. 
	 * @return Boolean value identifying if the sign is valid or not
	 */
	public Boolean verify(String plain, String sign, Map<String, Object> config);
	
}
