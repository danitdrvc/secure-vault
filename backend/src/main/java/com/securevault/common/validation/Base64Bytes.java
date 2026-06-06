package com.securevault.common.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Bean Validation constraint: vrednost mora biti validan standardni base64 čiji
 * dekodirani bajt-niz pada u {@code [min, max]}.
 *
 * <p>Koristi se da se kripto artefakti (salt, authKey, encUsk, publicKey, encPrivateKey)
 * provere po veličini/formatu — čime se odbija slučajno/zlonamerno poslat plaintext ključ
 * pogrešne dužine (DEVELOPMENT_PLAN Faza 3). Provera veličine je sanity-guard; pravu
 * zero-knowledge garanciju daje arhitektura (klijent šifruje, server skladišti bajtove).
 */
@Documented
@Constraint(validatedBy = Base64BytesValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.RECORD_COMPONENT})
@Retention(RetentionPolicy.RUNTIME)
public @interface Base64Bytes {

    String message() default "neispravan base64 ili neočekivana veličina dekodiranog sadržaja";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    /** Minimalan broj dekodiranih bajtova (uključivo). */
    int min() default 1;

    /** Maksimalan broj dekodiranih bajtova (uključivo). */
    int max() default Integer.MAX_VALUE;
}
