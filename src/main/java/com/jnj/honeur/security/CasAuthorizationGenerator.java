package com.jnj.honeur.security;

import org.pac4j.core.authorization.generator.AuthorizationGenerator;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.profile.CommonProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;

/**
 * Adds roles and permissions to the CasProfile
 *
 * @author Peter Moorthamer
 */
public class CasAuthorizationGenerator<P extends CommonProfile> implements AuthorizationGenerator<P> {

    private static final Logger LOG = LoggerFactory.getLogger(CasAuthorizationGenerator.class);

    private static final String DEFAULT_REMEMBER_ME_ATTRIBUTE_NAME = "longTermAuthenticationRequestTokenUsed";
    private static final String ROLE_ATTRIBUTE_NAME = "role";
    private static final String PERMISSION_ATTRIBUTE_NAME = "permission";

    public P generate(final WebContext context, final P profile) {
        processRememberMe(profile);
        processRoles(profile);
        processPermissions(profile);
        return profile;
    }

    private void processRememberMe(final P profile) {
        String rememberMeValue = (String) profile.getAttribute(DEFAULT_REMEMBER_ME_ATTRIBUTE_NAME);
        boolean isRemembered = rememberMeValue != null && Boolean.parseBoolean(rememberMeValue);
        profile.setRemembered(isRemembered);
    }

    private void processRoles(final P profile) {
        Object roleObj = profile.getAttribute(ROLE_ATTRIBUTE_NAME);
        if( roleObj instanceof Collection) {
            profile.addRoles((Collection)roleObj);
        } else if (roleObj instanceof String){
            profile.addRole((String)roleObj);
        }
        LOG.warn("No roles found in CasProfile!");
    }

    private void processPermissions(final P profile) {
        Object permissionObj = profile.getAttribute(PERMISSION_ATTRIBUTE_NAME);
        if(permissionObj instanceof Collection) {
            profile.addPermissions((Collection)permissionObj);
        } else if(permissionObj instanceof String){
            profile.addPermission((String) permissionObj);
        }
        LOG.warn("No permissions found in CasProfile!");
    }

}
