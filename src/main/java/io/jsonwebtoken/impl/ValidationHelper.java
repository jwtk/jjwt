package io.jsonwebtoken.impl;

import java.text.SimpleDateFormat;
import java.util.Date;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Clock;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.PrematureJwtException;

/**
 * This class contains static methods for validation of JWT claims.
 */
public class ValidationHelper {

	private static final String ISO_8601_FORMAT = "yyyy-MM-dd'T'HH:mm:ss'Z'";

	/**
	 * Check if JWT expired.
	 * 
	 * @param claims
	 *            Parsed claims value of JWT.
	 * @return {@code true} if current time is later than given {@code exp}
	 *         claim.
	 */
	public static boolean isExpired(Claims claims) {
		boolean expired = false;
		try {
			validateExpiration(claims);
		} catch (ExpiredJwtException e) {
			expired = true;
		}
		return expired;
	}

	/**
	 * Check if JWT is premature.
	 * 
	 * @param claims
	 *            Parsed claims value of JWT.
	 * @return {@code true} if current time is earlier than given {@code nbf}
	 *         claim.
	 */
	public static boolean isPremature(Claims claims) {
		boolean premature = false;
		try {
			validateNotBefore(claims);
		} catch (PrematureJwtException e) {
			premature = true;
		}
		return premature;
	}

	/**
	 * Validate {@code exp} (expires) claim. If current time is later than given
	 * {@code exp}, a {@link ExpiredJwtException} will be thrown.
	 * 
	 * @param claims
	 *            Parsed claims value of JWT.
	 */
	public static void validateExpiration(Claims claims) {
		validateExpiration(claims, 0, DefaultClock.INSTANCE);
	}

	/**
	 * Validate {@code exp} (expires) claim. If current time is later than given
	 * {@code exp}, a {@link ExpiredJwtException} will be thrown.
	 * 
	 * @param header
	 *            Parsed header value of JWT.
	 * @param claims
	 *            Parsed claims value of JWT.
	 * @param allowedClockSkewMillis
	 *            The number of seconds to tolerate for clock skew when
	 *            verifying {@code exp} claim.
	 * @param clock
	 *            a {@code Clock} object to return the timestamp to use when
	 *            validating the parsed JWT.
	 */
	public static void validateExpiration(Claims claims, long allowedClockSkewMillis, Clock clock) {
		validateExpiration(null, claims, allowedClockSkewMillis, clock);
	}

	/**
	 * Validate {@code exp} (expires) claim. If current time is later than given
	 * {@code exp}, a {@link ExpiredJwtException} will be thrown.
	 * 
	 * @param header
	 *            Parsed header value of JWT.
	 * @param claims
	 *            Parsed claims value of JWT.
	 * @param allowedClockSkewMillis
	 *            The number of seconds to tolerate for clock skew when
	 *            verifying {@code exp} claim.
	 * @param clock
	 *            a {@code Clock} object to return the timestamp to use when
	 *            validating the parsed JWT.
	 */
	public static void validateExpiration(Header header, Claims claims, long allowedClockSkewMillis, Clock clock) {
		SimpleDateFormat sdf;
		Date exp = claims.getExpiration();
		if (exp != null) {
			final Date now = clock.now();
			long nowTime = now.getTime();
			final boolean allowSkew = allowedClockSkewMillis > 0;
			long maxTime = nowTime - allowedClockSkewMillis;
			Date max = allowSkew ? new Date(maxTime) : now;
			if (max.after(exp)) {
				sdf = new SimpleDateFormat(ISO_8601_FORMAT);
				String expVal = sdf.format(exp);
				String nowVal = sdf.format(now);

				long differenceMillis = maxTime - exp.getTime();

				String msg = "JWT expired at " + expVal + ". Current time: " + nowVal + ", a difference of "
						+ differenceMillis + " milliseconds.  Allowed clock skew: " + allowedClockSkewMillis
						+ " milliseconds.";
				throw new ExpiredJwtException(header, claims, msg);
			}
		}
	}

	/**
	 * Validate {@code nbf} (not before) claim. If current time is earlier than
	 * given {@code nbf}, a {@link PrematureJwtException} will be thrown.
	 * 
	 * @param claims
	 *            Parsed claims value of JWT.
	 */
	public static void validateNotBefore(Claims claims) {
		validateNotBefore(claims, 0, DefaultClock.INSTANCE);
	}

	/**
	 * Validate {@code nbf} (not before) claim. If current time is earlier than
	 * given {@code nbf}, a {@link PrematureJwtException} will be thrown.
	 * 
	 * @param header
	 *            Parsed header value of JWT.
	 * @param claims
	 *            Parsed claims value of JWT.
	 * @param allowedClockSkewMillis
	 *            The number of seconds to tolerate for clock skew when
	 *            verifying {@code nbf} claim.
	 * @param clock
	 *            a {@code Clock} object to return the timestamp to use when
	 *            validating the parsed JWT.
	 */
	public static void validateNotBefore(Claims claims, long allowedClockSkewMillis, Clock clock) {
		validateNotBefore(null, claims, allowedClockSkewMillis, clock);
	}
	
	/**
	 * Validate {@code nbf} (not before) claim. If current time is earlier than
	 * given {@code nbf}, a {@link PrematureJwtException} will be thrown.
	 * 
	 * @param header
	 *            Parsed header value of JWT.
	 * @param claims
	 *            Parsed claims value of JWT.
	 * @param allowedClockSkewMillis
	 *            The number of seconds to tolerate for clock skew when
	 *            verifying {@code nbf} claim.
	 * @param clock
	 *            a {@code Clock} object to return the timestamp to use when
	 *            validating the parsed JWT.
	 */
	public static void validateNotBefore(Header header, Claims claims, long allowedClockSkewMillis, Clock clock) {
		SimpleDateFormat sdf;
		Date nbf = claims.getNotBefore();
		if (nbf != null) {
			final Date now = clock.now();
			long nowTime = now.getTime();
			final boolean allowSkew = allowedClockSkewMillis > 0;
			long minTime = nowTime + allowedClockSkewMillis;
			Date min = allowSkew ? new Date(minTime) : now;
			if (min.before(nbf)) {
				sdf = new SimpleDateFormat(ISO_8601_FORMAT);
				String nbfVal = sdf.format(nbf);
				String nowVal = sdf.format(now);

				long differenceMillis = nbf.getTime() - minTime;

				String msg = "JWT must not be accepted before " + nbfVal + ". Current time: " + nowVal
						+ ", a difference of " + differenceMillis + " milliseconds.  Allowed clock skew: "
						+ allowedClockSkewMillis + " milliseconds.";
				throw new PrematureJwtException(header, claims, msg);
			}
		}
	}

}
