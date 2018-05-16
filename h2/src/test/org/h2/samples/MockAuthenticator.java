package org.h2.samples;

import java.io.File;
import java.io.FileWriter;

import org.h2.tools.Server;

public class MockAuthenticator {

    static final String CONFIGURATION="<h2Auth allowUserRegistration=\"true\" createMissingRoles=\"true\">" +
	        "<validator realmName=\"mock\" className=\"org.h2.security.auth.impl.DummyCredentialsValidator\">"+
	            "<property name=\"password\" value=\"mock\" />"+
	        "</validator>"+
	        "<validator realmName=\"ldap\" className=\"org.h2.security.auth.impl.LdapCredentialsValidator\">"+
	            "<property name=\"bindDnPattern\" value=\"uid=%u,ou=users,dc=example,dc=com\" />"+
	            "<property name=\"host\" value=\"127.0.0.1\" />"+
	            "<property name=\"port\" value=\"636\" />"+
	        "</validator>"+
	        "<userToRolesMapper className=\"org.h2.security.auth.impl.StaticRolesMapper\">"+
	            "<property name=\"roles\" value=\"remoteUser,mock\"/>"+
	        "</userToRolesMapper>"+
        "</h2Auth>";
    public static void main(String... args) throws Exception {
        File configFile = File.createTempFile("h2auth","xml");
        try ( FileWriter writer = new FileWriter(configFile) ) {
            writer.write(CONFIGURATION);
        }
        System.setProperty("h2.authenticator","default");
        System.setProperty("h2auth.configurationFile",configFile.toURI().toString());
        Server.main("-tcpSSL");
    }
}
