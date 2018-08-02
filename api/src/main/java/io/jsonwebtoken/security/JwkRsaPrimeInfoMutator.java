package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface JwkRsaPrimeInfoMutator<T extends JwkRsaPrimeInfoMutator> {

    T setPrime(String r);

    T setCrtExponent(String d);

    T setCrtCoefficient(String t);
}
