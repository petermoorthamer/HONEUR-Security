package com.jnj.honeur.security;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class CasBCryptPasswordEncoder implements PasswordEncoder {

    private static final int STRENGTH = 8;

    private PasswordEncoder passwordEncoder;

    public CasBCryptPasswordEncoder() {
        this.passwordEncoder =  new BCryptPasswordEncoder(STRENGTH);
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return passwordEncoder.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return passwordEncoder.matches(rawPassword, encodedPassword);
    }
}
