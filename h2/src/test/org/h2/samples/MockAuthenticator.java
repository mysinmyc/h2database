package org.h2.samples;

import java.io.File;
import java.io.FileWriter;
import org.h2.server.ShutdownHandler;
import org.h2.tools.Server;

/**
 * This sample start an h2 server configured with external authentication
 * 
 * authentication realm: mock = authenticate any user with password mock ldap =
 * authenticate user to LDAP. It requires a local LDAP listening on port 10309
 * (no ssl). User dn must be uid=%u,ou=people,dc=example,dc=com jaas = similar
 * to ldap, byt authenticate users by using JAAS.
 *
 */
public class MockAuthenticator {

    static final String CONFIGURATION = "<h2Auth allowUserRegistration=\"true\" createMissingRoles=\"true\">"
            + "<validator realmName=\"mock\" className=\"org.h2.security.auth.impl.FixedPasswordCredentialsValidator\">"
            + "<property name=\"password\" value=\"mock\" />" + "</validator>"
            + "<validator realmName=\"ldap\" className=\"org.h2.security.auth.impl.LdapCredentialsValidator\">"
            + "<property name=\"bindDnPattern\" value=\"uid=%u,ou=people,dc=example,dc=com\" />"
            + "<property name=\"host\" value=\"127.0.0.1\" />" + "<property name=\"port\" value=\"10389\" />"
            + "<property name=\"secure\" value=\"false\" />" + "</validator>"
            + "<validator realmName=\"jaas\" className=\"org.h2.security.auth.impl.JaasCredentialsValidator\">"
            + "<property name=\"appName\" value=\"mockAuthenticator\" />" + "</validator>"
            + "<userToRolesMapper className=\"org.h2.security.auth.impl.AssignRealmNameRole\"/>"
            + "<userToRolesMapper className=\"org.h2.security.auth.impl.StaticRolesMapper\">"
            + "<property name=\"roles\" value=\"remoteUser,mock\"/>" + "</userToRolesMapper>" + "</h2Auth>";

    public static final String JAAS_CONF = "mockAuthenticator {\n"
            + "com.sun.security.auth.module.LdapLoginModule REQUIRED " + "userProvider=\"ldap://127.0.0.1:10389\" "
            + "authIdentity=\"uid={USERNAME},ou=people,dc=example,dc=com\" " + "debug=true " + "useSSL=false " + ";"
            + "\n};";

    public static void main(String... args) throws Exception {
        final File jaasConfigFile = File.createTempFile("jaas", ".conf");
        try (FileWriter writer = new FileWriter(jaasConfigFile)) {
            writer.write(JAAS_CONF);
        }
        System.setProperty("java.security.auth.login.config", jaasConfigFile.toURI().toString());
        final File configFile = File.createTempFile("h2auth", ".xml");
        try (FileWriter writer = new FileWriter(configFile)) {
            writer.write(CONFIGURATION);
        }
        System.setProperty("h2.authenticator", "default");
        System.setProperty("h2auth.configurationFile", configFile.toURI().toString());
        Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
            @Override
            public void run() {
                if (jaasConfigFile != null && jaasConfigFile.exists()) {
                    jaasConfigFile.delete();
                }
                if (configFile != null && configFile.exists()) {
                    configFile.delete();
                }
            }
        }));
        Server.main("-tcpSSL");
    }
}
