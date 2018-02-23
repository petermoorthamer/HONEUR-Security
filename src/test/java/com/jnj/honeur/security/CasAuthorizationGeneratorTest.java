package com.jnj.honeur.security;

import org.junit.Before;
import org.junit.Test;
import org.pac4j.cas.profile.CasProfile;
import org.pac4j.core.profile.CommonProfile;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

public class CasAuthorizationGeneratorTest {

    private static final String ROLE_ADMIN = "ROLE_ADMIN";
    private static final String ROLE_USER = "ROLE_USER";

    private CasProfile casProfile;

    @Before
    public void setup() {
        List<String> roles = new ArrayList<>();
        roles.add(ROLE_ADMIN);
        roles.add(ROLE_USER);

        List<String> permissions = new ArrayList<>();
        permissions.add("user:get");
        permissions.add("role:get");
        permissions.add("permission:get");

        casProfile = new CasProfile();
        casProfile.addAttribute("role", roles);
        casProfile.addAttribute("permission", permissions);
    }

    @Test
    public void generateEmpty() {
        CasProfile emptyCasProfile = new CasProfile();
        CommonProfile profile = new CasAuthorizationGenerator<>().generate(null, emptyCasProfile);

        assertFalse(profile.isRemembered());
        assertTrue(profile.getRoles().isEmpty());
        assertTrue(profile.getPermissions().isEmpty());
        assertSame(emptyCasProfile, profile);
    }

    @Test
    public void generateRolesAndPermissions() {

        assertFalse(casProfile.isRemembered());
        assertTrue(casProfile.getRoles().isEmpty());
        assertTrue(casProfile.getPermissions().isEmpty());

        CommonProfile profile = new CasAuthorizationGenerator<>().generate(null, casProfile);

        assertSame(casProfile, profile);

        assertFalse(profile.isRemembered());

        assertNotNull(profile.getRoles());
        assertEquals(2, profile.getRoles().size());
        assertTrue(profile.getRoles().contains(ROLE_ADMIN));
        assertTrue(profile.getRoles().contains(ROLE_USER));

        assertNotNull(profile.getPermissions());
        assertEquals(3, profile.getPermissions().size());
        assertTrue(profile.getPermissions().contains("user:get"));
        assertTrue(profile.getPermissions().contains("role:get"));
        assertTrue(profile.getPermissions().contains("permission:get"));
    }

    @Test
    public void generateRememberMeMissing() {
        CommonProfile profile = new CasAuthorizationGenerator<>().generate(null, casProfile);
        assertFalse(profile.isRemembered());
    }

    @Test
    public void generateRememberMeFalse() {
        casProfile.addAttribute("longTermAuthenticationRequestTokenUsed", "false");
        CommonProfile profile = new CasAuthorizationGenerator<>().generate(null, casProfile);
        assertFalse(profile.isRemembered());
    }

    @Test
    public void generateRememberMeTrue() {
        casProfile.addAttribute("longTermAuthenticationRequestTokenUsed", "true");
        CommonProfile profile = new CasAuthorizationGenerator<>().generate(null, casProfile);
        assertTrue(profile.isRemembered());
    }
}