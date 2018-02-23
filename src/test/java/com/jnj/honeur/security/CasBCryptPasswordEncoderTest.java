package com.jnj.honeur.security;

import org.junit.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import static org.junit.Assert.assertTrue;

public class CasBCryptPasswordEncoderTest {

    private static final String RAW_PASSWORD = "TheBestPasswordEver";

    @Test
    public void encode() {
        System.out.println(new CasBCryptPasswordEncoder().encode("test"));
    }

    @Test
    public void matches() {
        long start = System.currentTimeMillis();
        String encodedPassword = new CasBCryptPasswordEncoder().encode(RAW_PASSWORD);
        long current = System.currentTimeMillis();
        System.out.println(String.format("Encoding took: %s ms", current - start));

        start = current;
        assertTrue(new CasBCryptPasswordEncoder().matches(RAW_PASSWORD, encodedPassword));
        current = System.currentTimeMillis();
        System.out.println(String.format("Matching took: %s ms", current - start));

        start = current;
        assertTrue(new BCryptPasswordEncoder(8).matches(RAW_PASSWORD, encodedPassword));
        current = System.currentTimeMillis();
        System.out.println(String.format("Matching took: %s ms", current - start));

        start = current;
        new BCryptPasswordEncoder(8).encode(RAW_PASSWORD);
        current = System.currentTimeMillis();
        System.out.println(String.format("Encoding took: %s ms", current - start));
    }
}