/*
 * Copyright 2004-2018 H2 Group. Multiple-Licensed under the MPL 2.0,
 * and the EPL 1.0 (http://h2database.com/html/license.html).
 * Initial Developer: Alessandro Ventura
 */
package org.h2.test.auth;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Properties;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;
import javax.security.auth.login.Configuration;

import org.h2.engine.ConnectionInfo;
import org.h2.engine.Database;
import org.h2.engine.Engine;
import org.h2.engine.Role;
import org.h2.engine.Session;
import org.h2.engine.User;
import org.h2.security.auth.AuthenticationManager;
import org.h2.security.auth.DefaultAuthenticator;
import org.h2.security.auth.impl.AssignRealmNameRole;
import org.h2.security.auth.impl.JaasCredentialsValidator;
import org.h2.security.auth.impl.StaticRolesMapper;
import org.h2.test.TestBase;
import org.h2.util.MathUtils;
import org.postgresql.core.Utils;

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
            Session session = Engine.getInstance().createSession(connectionInfo);
            Database database = session.getDatabase();
            Role externalRole = new Role(database, database.allocateObjectId(), "@" + getRealmName().toUpperCase(),
                    false);
            session.getDatabase().addDatabaseObject(session, externalRole);
            session.commit(false);
            try {
                try {
                    Connection wrongLoginConnection = DriverManager.getConnection(getDatabaseURL(), getExternalUser(),
                            "");
                    wrongLoginConnection.close();
                    throw new Exception("user should not be able to login with an invalid password");
                } catch (SQLException e) {
                }
                try {
                    Connection wrongLoginConnection = DriverManager.getConnection(
                            getDatabaseURL().replaceAll("AUTHREALM=.*$", ""), getExternalUser(),
                            getExternalUserPassword());
                    wrongLoginConnection.close();
                    throw new Exception("user should not be able to login without a realm");
                } catch (SQLException e) {
                }
                Connection rightConnection = DriverManager.getConnection(getDatabaseURL(), getExternalUser(),
                        getExternalUserPassword());
                try {
                    User user = session.getDatabase()
                            .findUser((getExternalUser() + "@" + getRealmName()).toUpperCase());
                    assertNotNull(user);
                    assertTrue(user.isRoleGranted(externalRole));
                } finally {
                    rightConnection.close();
                }
            } finally {
                session.close();
            }
        } finally {
            Configuration.setConfiguration(oldConfiguration);
        }
    }
}