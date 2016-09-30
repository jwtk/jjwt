package io.jsonwebtoken.impl;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Date;

import org.junit.Test;

import io.jsonwebtoken.Claims;

public class ValidationHelperTest {

	@Test
	public void shouldReturnTrueWhenTokenIsExpired() throws Exception {

		// given
		Date now = new Date();
		Date recent = new Date(now.getTime() - 1);
		Claims claims = new DefaultClaims();

		claims.setExpiration(recent);

		// when
		boolean expired = ValidationHelper.isExpired(claims);

		// then
		assertTrue(expired);
	}
	
	@Test
	public void shouldReturnFalseWhenTokenIsNotExpired() throws Exception {

		// given
		Date now = new Date();
		Date future = new Date(now.getTime() + (1000*1000));
		Claims claims = new DefaultClaims();

		claims.setExpiration(future);

		// when
		boolean expired = ValidationHelper.isExpired(claims);

		// then
		assertFalse(expired);
	}
	
	
	@Test
	public void shouldReturnTrueWhenTokenIsPremature() throws Exception {

		// given
		Date now = new Date();
		Date future = new Date(now.getTime() + (1000*1000));
		Claims claims = new DefaultClaims();

		claims.setNotBefore(future);

		// when
		boolean premature = ValidationHelper.isPremature(claims);

		// then
		assertTrue(premature);
	}
	
	@Test
	public void shouldReturnFalseWhenTokenIsNotPremature() throws Exception {

		// given
		Date now = new Date();
		Date recent = new Date(now.getTime() - 1);
		Claims claims = new DefaultClaims();

		claims.setNotBefore(recent);

		// when
		boolean premature = ValidationHelper.isPremature(claims);

		// then
		assertFalse(premature);
	}
}
