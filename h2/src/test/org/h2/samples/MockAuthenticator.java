package org.h2.samples;

import java.io.File;
import java.io.FileWriter;

import org.h2.security.auth.impl.AssignRealmNameRole;
import org.h2.security.auth.impl.StaticUserCredentialsValidator;
import org.h2.security.auth.impl.JaasCredentialsValidator;
import org.h2.security.auth.impl.LdapCredentialsValidator;
import org.h2.security.auth.impl.StaticRolesMapper;
import org.h2.server.ShutdownHandler;
import org.h2.tools.Server;

/**
 * This sample start an h2 server configured with external authentication
 * 
 * authentication realms:
 *    mock = authenticate any user with password mock
 *    ldap = authenticate user to LDAP. It requires a local LDAP listening on port 10309
 *           (no ssl). User dn must be uid=%u,ou=people,dc=example,dc=com
 *    jaas = similar to ldap, but authenticate users by using JAAS.
 *
 */
public class MockAuthenticator {

    static final String H2AUTH_XML = "<h2Auth allowUserRegistration=\"true\" createMissingRoles=\"true\">"
            + "\n\t<realm name=\"mock\" validatorClass=\""+StaticUserCredentialsValidator.class.getName()+"\">"
            + "\n\t\t<property name=\"password\" value=\"mock\" />"
            + "\n\t</realm>"
            + "\n\t<realm name=\"ldap\" validatorClass=\""+LdapCredentialsValidator.class.getName()+"\">"
            + "\n\t\t<property name=\"bindDnPattern\" value=\"uid=%u,ou=people,dc=example,dc=com\" />"
            + "\n\t\t<property name=\"host\" value=\"127.0.0.1\" />"
            + "\n\t\t<property name=\"port\" value=\"10389\" />"
            + "\n\t\t<property name=\"secure\" value=\"false\" />"
            + "\n\t</realm>"
            + "\n\t<realm name=\"ldaps\" validatorClass=\""+LdapCredentialsValidator.class.getName()+"\">"
            + "\n\t\t<property name=\"bindDnPattern\" value=\"uid=%u,ou=people,dc=example,dc=com\" />"
            + "\n\t\t<property name=\"host\" value=\"127.0.0.1\" />"
            + "\n\t\t<property name=\"port\" value=\"10636\" />"
            + "\n\t\t<property name=\"secure\" value=\"true\" />"
            + "\n\t</realm>"            
            + "\n\t<realm name=\"jaas\" validatorClass=\""+JaasCredentialsValidator.class.getName()+"\">"
            + "\n\t\t<property name=\"appName\" value=\"mockAuthenticator\" />"
            + "\n\t</realm>"
            + "\n\t<userToRolesMapper class=\""+AssignRealmNameRole.class.getName()+"\"/>"
            + "\n\t<userToRolesMapper class=\""+StaticRolesMapper.class.getName()+"\">"
            + "\n\t\t<property name=\"roles\" value=\"remoteUser,mock\"/>"
            + "\n\t</userToRolesMapper>"
            + "\n</h2Auth>";

    public static final String JAAS_CONF = "mockAuthenticator {\n"
            + "com.sun.security.auth.module.LdapLoginModule REQUIRED " + "userProvider=\"ldap://127.0.0.1:10389\" "
            + "authIdentity=\"uid={USERNAME},ou=people,dc=example,dc=com\" " + "debug=true " + "useSSL=false " + ";"
            + "\n};";

    public static void main(String... args) throws Exception {
        System.out.println("---- jaas.conf file ----\n"+JAAS_CONF+"\n---- end of jaas.conf file ----");
        System.out.println("---- h2auth.xml file ----\n"+H2AUTH_XML+"\n---- end of h2auth.xml file ----");
        final File jaasConfigFile = File.createTempFile("jaas", ".conf");
        try (FileWriter writer = new FileWriter(jaasConfigFile)) {
            writer.write(JAAS_CONF);
        }
        System.setProperty("java.security.auth.login.config", jaasConfigFile.toURI().toString());
        final File configFile = File.createTempFile("h2auth", ".xml");
        try (FileWriter writer = new FileWriter(configFile)) {
            writer.write(H2AUTH_XML);
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
