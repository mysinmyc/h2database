/*
 * Copyright 2004-2018 H2 Group. Multiple-Licensed under the MPL 2.0,
 * and the EPL 1.0 (http://h2database.com/html/license.html).
 * Initial Developer: Alessandro Ventura
 */
package org.h2.security.auth.impl;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.h2.api.UserToRolesMapper;
import org.h2.security.auth.AuthenticationException;
import org.h2.security.auth.AuthenticationInfo;
import org.h2.security.auth.ConfigProperties;

/**
 * Assign static roles to authenticated users
 * 
 * parameters:
 *   roles = role list separated by comma
 */
public class StaticRolesMapper implements UserToRolesMapper {

    Set<String> roles;
    
    @Override
    public void configure(ConfigProperties configProperties) {
        roles = new HashSet<>(Arrays.asList(configProperties.getStringValue("roles", "").split(",")));
    }

    @Override
    public Set<String> mapUserToRoles(AuthenticationInfo authenticationInfo) throws AuthenticationException {
        return roles;
    }

}
