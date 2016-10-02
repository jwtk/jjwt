package io.jsonwebtoken;

public interface Validator<T> {
	void validate(T value);
}
