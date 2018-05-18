/*
 * Copyright 2004-2018 H2 Group. Multiple-Licensed under the MPL 2.0,
 * and the EPL 1.0 (http://h2database.com/html/license.html).
 * Initial Developer: Alessandro Ventura
 */
package org.h2.api;

import org.h2.engine.Database;
import org.h2.engine.User;
import org.h2.security.auth.AuthConfigException;
import org.h2.security.auth.AuthenticationException;
import org.h2.security.auth.AuthenticationInfo;

/**
 * Low level interface to implement full authentication process
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
    
    /**
     * Initialize the authenticator. This method is invoked by AuthenticationManager
     * when the authenticator is set
     * @throws AuthConfigException
     */
    void init() throws AuthConfigException;
}
