package com.securevault.common.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.Base64;

/**
 * Validator za {@link Base64Bytes}. Null prepušta {@code @NotBlank}-u; nevalidan base64
 * (strogi dekoder bez whitespace-a) ili dužina van opsega → nevalidno.
 */
public class Base64BytesValidator implements ConstraintValidator<Base64Bytes, String> {

    private int min;
    private int max;

    @Override
    public void initialize(Base64Bytes annotation) {
        this.min = annotation.min();
        this.max = annotation.max();
    }

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null) {
            return true; // prisustvo pokriva @NotBlank
        }
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException ex) {
            return false;
        }
        return decoded.length >= min && decoded.length <= max;
    }
}
