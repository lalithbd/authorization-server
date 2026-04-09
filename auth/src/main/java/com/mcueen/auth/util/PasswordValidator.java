package com.mcueen.auth.util;

import com.mcueen.auth.exception.AuthServiceException;
import org.springframework.http.HttpStatus;

import java.util.regex.Pattern;

public final class PasswordValidator {

    private PasswordValidator() {}

    private static final int MIN_LENGTH = 10;
    private static final Pattern UPPERCASE = Pattern.compile("[A-Z]");
    private static final Pattern LOWERCASE = Pattern.compile("[a-z]");
    private static final Pattern DIGIT = Pattern.compile("[0-9]");
    private static final Pattern SYMBOL = Pattern.compile("[^a-zA-Z0-9]");

    public static void validate(String password) throws AuthServiceException {
        if (password == null || password.length() < MIN_LENGTH) {
            throw new AuthServiceException(HttpStatus.BAD_REQUEST, "Password must be at least " + MIN_LENGTH + " characters");
        }
        if (!UPPERCASE.matcher(password).find()) {
            throw new AuthServiceException(HttpStatus.BAD_REQUEST, "Password must contain at least one uppercase letter");
        }
        if (!LOWERCASE.matcher(password).find()) {
            throw new AuthServiceException(HttpStatus.BAD_REQUEST, "Password must contain at least one lowercase letter");
        }
        if (!DIGIT.matcher(password).find()) {
            throw new AuthServiceException(HttpStatus.BAD_REQUEST, "Password must contain at least one number");
        }
        if (!SYMBOL.matcher(password).find()) {
            throw new AuthServiceException(HttpStatus.BAD_REQUEST, "Password must contain at least one special character");
        }
    }
}
