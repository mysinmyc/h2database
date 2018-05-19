/*
 * Copyright 2004-2018 H2 Group. Multiple-Licensed under the MPL 2.0,
 * and the EPL 1.0 (http://h2database.com/html/license.html).
 * Initial Developer: Alessandro Ventura
 */
package org.h2.test.auth;

import java.util.Properties;

import javax.security.auth.login.Configuration;

import org.h2.engine.ConnectionInfo;
import org.h2.engine.Engine;
import org.h2.engine.Role;
import org.h2.security.auth.DefaultAuthenticator;
import org.h2.security.auth.impl.JaasCredentialsValidator;
import org.h2.test.TestBase;

public class TestAuthenticationDefaults extends TestAuthentication {

    public static void main(String... a) throws Exception {
        TestBase.createCaller().init().test();
    }

    @Override
    String getRealmName() {
        return DefaultAuthenticator.DEFAULT_REALMNAME;
    }

    @Override
    String getJaasConfigName() {
        return JaasCredentialsValidator.DEFAULT_APPNAME;
    }

    @Override
    void configureAuthentication() {
        System.setProperty("h2.authenticator","on");
    }

    @Override
    public void test() throws Exception {
        Configuration oldConfiguration = Configuration.getConfiguration();
        try {
            configureAuthentication();
            configureJaas();
            Properties properties = new Properties();
            ConnectionInfo connectionInfo = new ConnectionInfo(getDatabaseURL(), properties);
            session = Engine.getInstance().createSession(connectionInfo);
            database = session.getDatabase();
            try {
                testInvalidPassword();
                testExternalUserWihoutRealm();
                testExternalUser();
                testAssignRealNameRole();
            } finally {
                session.close();
            }
        } finally {
            Configuration.setConfiguration(oldConfiguration);
        }
    }
}