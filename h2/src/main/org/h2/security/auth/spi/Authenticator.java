/*
 * Copyright 2004-2018 H2 Group. Multiple-Licensed under the MPL 2.0,
 * and the EPL 1.0 (http://h2database.com/html/license.html).
 * Initial Developer: Alessandro Ventura
 */
package org.h2.security.auth.spi;

import org.h2.engine.Database;
import org.h2.engine.User;
import org.h2.security.auth.AuthenticationException;
import org.h2.security.auth.AuthenticationInfo;

/**
 * Authenticator is responsible to validate user credentials (typically username
 * and password) and map credentials to a valid database user
 */
public interface Authenticator {

    /**
     * perform user authentication
     * 
     * @param authenticationInfo
     * @param database
     * @return valid database user or null if user doesn't exists in the database
     * @throws AuthenticationException
     */
    User authenticate(AuthenticationInfo authenticationInfo, Database database) throws AuthenticationException;
}
