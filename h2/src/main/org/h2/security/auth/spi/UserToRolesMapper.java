/*
 * Copyright 2004-2018 H2 Group. Multiple-Licensed under the MPL 2.0,
 * and the EPL 1.0 (http://h2database.com/html/license.html).
 * Initial Developer: Alessandro Ventura
 */
package org.h2.security.auth.spi;

import java.util.Set;
import org.h2.security.auth.AuthenticationException;
import org.h2.security.auth.AuthenticationInfo;

/**
 * Implement this interface to define roles granted to the user
 */
public interface UserToRolesMapper extends Configurable {

    /**
     * Map user identified by authentication info to a set of granted roles 
     * @param authenticationInfo
     * @return list of roles to be assigned to the user temporary
     * @throws AuthenticationException
     */
    Set<String> mapUserToRoles(AuthenticationInfo authenticationInfo) throws AuthenticationException;
}
