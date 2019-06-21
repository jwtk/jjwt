package io.jsonwebtoken.impl;

import java.util.Map;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtFactory;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.impl.DefaultClaims;
import io.jsonwebtoken.impl.DefaultHeader;
import io.jsonwebtoken.impl.DefaultJwsHeader;
import io.jsonwebtoken.impl.DefaultJwtBuilder;
import io.jsonwebtoken.impl.DefaultJwtParser;

public class DefaultJwtFactory implements JwtFactory {

	@Override
	public Header header() {
		return new DefaultHeader();
	}

	@Override
	public Header header(final Map<String, Object> map) {
		return new DefaultHeader(map);
	}

	@Override
	public JwsHeader jwsHeader() {
		return new DefaultJwsHeader();
	}

	@Override
	public JwsHeader jwsHeader(final Map<String, Object> header) {
		return new DefaultJwsHeader(header);
	}

	@Override
	public Claims claims() {
		return new DefaultClaims();
	}

	@Override
	public Claims claims(final Map<String, Object> claims) {
		return new DefaultClaims(claims);
	}

	@Override
	public JwtBuilder builder() {
		return new DefaultJwtBuilder();
	}

	@Override
	public JwtParser parser() {
		return new DefaultJwtParser();
	}
}
