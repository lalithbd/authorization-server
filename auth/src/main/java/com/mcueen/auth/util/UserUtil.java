package com.mcueen.auth.util;

import java.util.regex.Pattern;

public class UserUtil {

    public static final String DEFAULT_ROLE = "DEFAULT";

    public static boolean isValidPassword(String password) {
        if (password.length() < 8) {
            return false;
        }

        // Regex patterns for different character requirements
        Pattern lowerCasePattern = Pattern.compile(".*[a-z].*"); // at least one lowercase letter
        Pattern upperCasePattern = Pattern.compile(".*[A-Z].*"); // at least one uppercase letter
        Pattern digitPattern = Pattern.compile(".*\\d.*");         // at least one digit
        Pattern specialCharPattern = Pattern.compile(".*[!@#$%^&*(),.?\":{}|<>].*"); // at least one special character

        // Check if the password matches all the conditions
        boolean hasLowerCase = lowerCasePattern.matcher(password).matches();
        boolean hasUpperCase = upperCasePattern.matcher(password).matches();
        boolean hasDigit = digitPattern.matcher(password).matches();
        boolean hasSpecialChar = specialCharPattern.matcher(password).matches();

        // Return true if all conditions are met
        return hasLowerCase && hasUpperCase && hasDigit && hasSpecialChar;
    }
}
