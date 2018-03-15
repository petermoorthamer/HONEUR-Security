package com.jnj.honeur.security;

import org.pac4j.core.authorization.generator.AuthorizationGenerator;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.profile.CommonProfile;

public class RoleAdminAuthorizationGenerator implements AuthorizationGenerator<CommonProfile> {

    @Override
    public CommonProfile generate(final WebContext context, final CommonProfile profile) {
        profile.addRole("ROLE_ADMIN");
        profile.clearSensitiveData(); // remove the access token to reduce size and make the remember-me work
        profile.setRemembered(true);
        return profile;
    }
}