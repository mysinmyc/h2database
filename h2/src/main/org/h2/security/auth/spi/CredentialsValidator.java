/*
 * Copyright 2004-2018 H2 Group. Multiple-Licensed under the MPL 2.0,
 * and the EPL 1.0 (http://h2database.com/html/license.html).
 * Initial Developer: Alessandro Ventura
 */
package org.h2.security.auth.spi;

import org.h2.security.auth.AuthenticationInfo;

/*
 * Interface to implement to validate user credentials
 */
public interface CredentialsValidator extends Configurable {

    /**
     * Validate user credential
     * @param authenticationInfo = authentication info
     * @return true if credentials are valid, otherwise false
     * @throws Exception = any exception occurred (invalid credentials or internal issue) prevent user login
     */
    boolean validateCredentials(AuthenticationInfo authenticationInfo) throws Exception;

}
