package com.jnj.honeur.security;

import org.apache.shiro.subject.Subject;

import java.security.Principal;

public class SecurityUtils2 {

    public static String getSubjectName(final Subject subject) {
        if(subject == null) {
            return null;
        }
        if (subject.getPrincipal() != null) {
            Principal principal = (Principal)subject.getPrincipal();
            return principal.getName();
        }
        return null;
    }
}
