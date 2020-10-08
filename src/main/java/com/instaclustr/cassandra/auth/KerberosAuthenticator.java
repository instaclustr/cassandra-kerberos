/*
 * Licensed to Instaclustr Pty. Ltd. (Instaclustr) under one
 * or more contributor license agreements.  Instaclustr licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.instaclustr.cassandra.auth;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import org.apache.cassandra.auth.*;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.config.SchemaConstants;
import org.apache.cassandra.cql3.QueryOptions;
import org.apache.cassandra.cql3.QueryProcessor;
import org.apache.cassandra.cql3.UntypedResultSet;
import org.apache.cassandra.cql3.statements.SelectStatement;
import org.apache.cassandra.db.ConsistencyLevel;
import org.apache.cassandra.exceptions.AuthenticationException;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.exceptions.RequestExecutionException;
import org.apache.cassandra.service.ClientState;
import org.apache.cassandra.service.QueryState;
import org.apache.cassandra.transport.messages.ResultMessage;
import org.apache.cassandra.utils.ByteBufferUtil;
import org.apache.cassandra.utils.FBUtilities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslServer;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URL;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Collection;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * KerberosAuthenticator is an IAuthenticator implementation
 * that uses Kerberos to authenticate external Cassandra users.
 *
 * If the Cassandra user corresponding to the client's Kerberos
 * principal has been GRANTed access to additional roles, those
 * roles may be assumed directly if a role name is specified
 * with the SASL authorizationID.
 *
 * If an authorizationID is not provided, the client will
 * assume the Cassandra user corresponding to the client's
 * Kerberos principal.
 *
 * This IAuthenticator does not currently support legacy
 * authentication, therefore only C* 3.0+ is supported.
 */
public class KerberosAuthenticator implements IAuthenticator {

    private static final Logger logger = LoggerFactory.getLogger(KerberosAuthenticator.class);

    private static final String SASL_MECHANISM = "GSSAPI";

    // name of the role column.
    private static final String ROLE = "role";

    private Configuration config;

    private Subject subject;

    private SelectStatement getRoleStatement;
    private UserCache cache;

    @Override
    public boolean requireAuthentication()
    {
        return true;
    }

    @Override
    public Set<? extends IResource> protectedResources()
    {
        // Also protected by CassandraRoleManager, but the duplication doesn't hurt and is more explicit
        return ImmutableSet.of(DataResource.table(SchemaConstants.AUTH_KEYSPACE_NAME, AuthKeyspace.ROLES));
    }

    private static class Configuration
    {
        private URL configUrl;

        private File keytab;
        private String qop;
        private KerberosPrincipal servicePrincipal;

        static final String DEFAULT_CONFIGURATION = "cassandra-krb5.properties";
        static final String CONFIGURATION_KEYTAB_PATH_NAME = "keytab";
        static final String CONFIGURATION_QOP_NAME = "qop";
        static final String CONFIGURATION_SERVICE_PRINCIPAL_NAME = "service_principal";

        private static final String DEFAULT_KEYTAB_PATH = "cassandra.keytab";
        private static final String DEFAULT_QOP = "auth";

        private Configuration(){}

        public File keytab() {
            return keytab;
        }

        public String qop() {
            return qop;
        }

        public KerberosPrincipal servicePrincipal() {
            return servicePrincipal;
        }

        public String getKerberosPrincipalServiceNameComponent() {
            final Pattern kerberosPrincipalPattern = Pattern.compile("([^/@]*)(/([^/@]*))?@([^/@]*)");

            Matcher match = kerberosPrincipalPattern.matcher(this.servicePrincipal.toString());

            if (!match.matches())
                throw new RuntimeException("Config value for " + CONFIGURATION_SERVICE_PRINCIPAL_NAME + " in " +
                        configUrl.toString() + " is not valid. Kerberos principal must be in KRB_NT_SRV_HST format");

            return match.group(1);
        }

        private static URL getConfig(String rawUrl) throws ConfigurationException
        {
            URL url;
            try
            {
                url = new URL(rawUrl);
                url.openStream().close(); // catches well-formed but bogus URLs
            }
            catch (Exception e)
            {
                ClassLoader loader = KerberosAuthenticator.class.getClassLoader();
                url = loader.getResource(rawUrl);
                if (url == null)
                {
                    String required = "file:" + File.separator + File.separator;
                    throw new ConfigurationException("Cannot locate " + rawUrl + ".  " +
                            "If this is a local file, please confirm you've provided " +
                            required + File.separator + " as a URI prefix.");
                }
            }

            logger.debug("Kerberos configuration location: {}", url);
            return url;
        }

        private static File getKeytab(String path) throws  ConfigurationException {
            File file;

            file = new File(path);
            if (!file.isFile())
            {
                ClassLoader loader = KerberosAuthenticator.class.getClassLoader();
                URL url = loader.getResource(path);

                if (url == null)
                {
                    String required = "file:" + File.separator + File.separator;
                    throw new ConfigurationException("Cannot locate " + path + ".  " +
                            "If this is a local file, please confirm you've provided " +
                            required + File.separator + " as a URI prefix.");
                } else
                {
                    file = new File(url.getFile());
                }
            }

            logger.debug("Kerberos keytab location: {}", file.getAbsolutePath());
            return file;
        }

        private void load() throws ConfigurationException
        {
            if (configUrl == null)
                configUrl = getConfig(System.getProperty("cassandra.krb5.config", DEFAULT_CONFIGURATION));

            final Properties config = new Properties();
            try
            {
                logger.debug("Loading Kerberos settings from {}", configUrl);
                try (final InputStream is = configUrl.openStream())
                {
                    config.load(is);
                }
            }
            catch (IOException e)
            {
                throw new RuntimeException(e);
            }

            this.keytab = getKeytab(config.getProperty(CONFIGURATION_KEYTAB_PATH_NAME, DEFAULT_KEYTAB_PATH));
            this.qop = config.getProperty(CONFIGURATION_QOP_NAME, DEFAULT_QOP);
            this.servicePrincipal = new KerberosPrincipal(
                    config.getProperty(CONFIGURATION_SERVICE_PRINCIPAL_NAME), KerberosPrincipal.KRB_NT_SRV_HST);
        }

        void validate() throws ConfigurationException
        {

            // this should never happen
            if (this.servicePrincipal == null)
                throw new ConfigurationException("No value for " + CONFIGURATION_SERVICE_PRINCIPAL_NAME + " found in " + configUrl.toString());

            // this should never happen
            if (this.qop == null)
                throw new ConfigurationException("No value for " + CONFIGURATION_QOP_NAME + " found in " + configUrl.toString());

            final Collection<String> validQopValues = ImmutableList.<String>builder()
                    .add("auth").add("auth-conf").add("auth-int").build();

            if (!validQopValues.contains(this.qop))
                throw new ConfigurationException("Config value for " + CONFIGURATION_QOP_NAME + " in " +
                        configUrl.toString() + " is not valid. Valid values are: " + validQopValues.toString());

            if (!(this.keytab.isFile() && this.keytab.canRead()))
                throw new ConfigurationException("Keytab file " + keytab.getAbsolutePath() + " specified in " +
                        configUrl.toString() + " does not exist, is not a normal file, or cannot be read.");
        }

        static Configuration loadConfig() {
            final Configuration config = new Configuration();
            config.load();
            config.validate();
            return config;
        }
    }

    @Override
    public void validateConfiguration() throws ConfigurationException
    {
        // Load Kerberos configuration properties
        config = Configuration.loadConfig();
    }

    @Override
    public void setup()
    {
        subject = loginAsSubject(config.servicePrincipal(), config.keytab());

        // Prepare statement to check whether a role exists in Cassandra
        String query = String.format("SELECT %s FROM %s.%s WHERE role = ?",
                ROLE,
                SchemaConstants.AUTH_KEYSPACE_NAME,
                AuthKeyspace.ROLES);
        this.getRoleStatement = prepare(query);

        cache = new UserCache(this);
    }

    static String getKrb5LoginModuleName()
    {
        return System.getProperty("java.vendor").contains("IBM")
                ? "com.ibm.security.auth.module.Krb5LoginModule"
                : "com.sun.security.auth.module.Krb5LoginModule";
    }

    /**
     * Login using a Kerberos 5 service principal & keytab
     *
     * @param servicePrincipal A Kerberos 5 service principal
     * @param keytab A Kerberos 5 keytab file containing keys for the service principal
     * @return Authenticated Subject representing the principal
     */
    private static Subject loginAsSubject(KerberosPrincipal servicePrincipal, File keytab)
    {
        logger.debug("Logging in Kerberos service principal {} using keytab at {}", servicePrincipal, keytab.getAbsolutePath());

        final javax.security.auth.login.Configuration conf = new javax.security.auth.login.Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                return new AppConfigurationEntry[] {
                        new AppConfigurationEntry(
                                getKrb5LoginModuleName(),
                                AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                                ImmutableMap.<String, String>builder()
                                        .put("principal", servicePrincipal.toString())
                                        .put("useKeyTab", "true")
                                        .put("keyTab", keytab.getAbsolutePath())
                                        .put("storeKey", "true")
                                        .put("doNotPrompt", "true")
                                        .put("isInitiator", "false")
                                        .build()
                        )
                };
            }
        };

        try
        {
            // Don't need to supply a name, as it is ignored in the Configuration implementation
            final LoginContext loginContext = new LoginContext("", null, cbh -> {
                // Callback is called when login using the configuration fails
                throw new RuntimeException(new LoginException(String.format("Failed to establish a login context for " +
                        "principal %s with keytab at %s.", servicePrincipal, keytab.getAbsolutePath())));
                }, conf);
            loginContext.login();

            logger.debug("Login context established");
            return loginContext.getSubject();
        }
        catch (LoginException e)
        {
            throw new RuntimeException("Failed to establish a login context", e);
        }
    }

    private static SelectStatement prepare(String query)
    {
        return (SelectStatement) QueryProcessor.getStatement(query, ClientState.forInternalCalls()).statement;
    }

    @Override
    public SaslNegotiator newSaslNegotiator(InetAddress clientAddress)
    {

        final String saslProtocol = config.getKerberosPrincipalServiceNameComponent();
        final Map<String, String> saslProperties = ImmutableMap.<String, String>builder().put(Sasl.QOP, config.qop()).build();

        return new KerberosSaslAuthenticator(saslProtocol, saslProperties);
    }

    @Override
    public AuthenticatedUser legacyAuthenticate(Map<String, String> credentials) throws AuthenticationException
    {
        // Could potentially implement in the future using the Java GSS-API or SASL clients directly.
        throw new UnsupportedOperationException("Legacy authentication is not supported");
    }

    private class KerberosSaslAuthenticator implements SaslNegotiator
    {
        private final SaslServer saslServer;

        private AuthenticatedUser authenticatedUser = null;

        private KerberosSaslAuthenticator(final String saslProtocol, final Map<String, ?> saslProperties)
        {
            logger.debug("Creating SaslServer for {} with {} mechanism. SASL Protocol: {} SASL Properties: {}", config.servicePrincipal, SASL_MECHANISM, saslProtocol, saslProperties);
            try {
                this.saslServer = Subject.doAs(subject, (PrivilegedExceptionAction<SaslServer>) () ->
                        Sasl.createSaslServer(
                                SASL_MECHANISM,
                                saslProtocol,
                                FBUtilities.getBroadcastRpcAddress().getCanonicalHostName(),
                                saslProperties,
                                callbacks -> {
                                    for(final Callback cb: callbacks) {
                                        if (cb instanceof AuthorizeCallback) {
                                            handleAuthorizeCallback((AuthorizeCallback) cb);
                                        }
                                    }
                                }));
            } catch (PrivilegedActionException e) {
                throw new RuntimeException(e.getException());
            }
        }

        private void handleAuthorizeCallback(final AuthorizeCallback ac) throws AuthenticationException {
            ac.setAuthorizedID(null);
            ac.setAuthorized(false);

            // this should never happen
            if (ac.getAuthenticationID() == null)
            {
                logger.debug("Kerberos authentication succeeded, but the authentication ID is null.");

                // throw to client
                throw new AuthenticationException("Authentication ID must not be null");
            }

            // authentication ID is a Kerberos principal. We need to split the service/username component from the full
            // principal to use as the Cassandra user.
            final String clientPrincipal = ac.getAuthenticationID().split("[@/]")[0];

            // will throw an AuthenticationException if user does not exist
            final AuthenticatedUser principalUser = getCassandraUser(clientPrincipal);

            if (ac.getAuthorizationID() == null || ac.getAuthorizationID().equals(ac.getAuthenticationID()))
            {
                this.authenticatedUser = principalUser;
                ac.setAuthorizedID(principalUser.getName());
                ac.setAuthorized(true);
            }
            else
            {
                final AuthenticatedUser assumedUser = getCassandraUser(ac.getAuthorizationID());

                // If the user represented by the AuthenticationID (the client's Kerberos principal) has been GRANTed
                // the role represented by the AuthorizationID, then assume that role directly
                if (principalUser.getRoles().contains(assumedUser.getPrimaryRole()))
                {
                    this.authenticatedUser = assumedUser;
                    ac.setAuthorizedID(assumedUser.getName());
                    ac.setAuthorized(true);
                }
                else
                {
                    logger.debug("Kerberos client principal \"{}\" authenticated, but the Cassandra user \"{}\" " +
                                    "does not have permission to assume the role \"{}\" " +
                                    "specified by the authorization ID.",
                            ac.getAuthenticationID(), principalUser.getName(), assumedUser.getName());

                    // throw to client
                    throw new AuthenticationException(
                            String.format("Cassandra user \"%s\" is unable to assume the role \"%s\"",
                                    principalUser.getName(), assumedUser.getName()));
                }
            }

            if (ac.isAuthorized())
            {
                logger.debug("Kerberos client principal \"{}\" authorized as Cassandra user \"{}\"",
                        ac.getAuthenticationID(), ac.getAuthorizedID());
            }
        }

        @Override
        public byte[] evaluateResponse(final byte[] response) throws AuthenticationException
        {
            try
            {
                return Subject.doAs(subject, (PrivilegedExceptionAction<byte[]>) () ->
                        saslServer.evaluateResponse(response));
            }
            catch (PrivilegedActionException e)
            {
                logger.error("The SASL server could not evaluate the response sent by the client. " +
                        "Check that the authentication mechanism is configured correctly, and that the client " +
                        "is sending a valid SASL/{} response.", SASL_MECHANISM, e.getException());

                // throw to client
                throw new AuthenticationException("The SASL server could not evaluate the response sent by the client. " +
                        "The server may not be configured correctly, or the response may be invalid.");
            }
        }

        @Override
        public boolean isComplete()
        {
            return saslServer.isComplete() && (authenticatedUser != null);
        }

        @Override
        public AuthenticatedUser getAuthenticatedUser() throws AuthenticationException
        {
            if (!isComplete())
                throw new AuthenticationException("SASL negotiation is not complete");

            return authenticatedUser;
        }
    }

    /**
     * Check that a given pre-authenticated principal exists in Cassandra
     *
     * @param username Username of an externally-authenticated principal
     * @return authenticated Cassandra user
     */
    private AuthenticatedUser getCassandraUser(String username) throws AuthenticationException
    {
        try
        {
            // This will throw an exception if the username does not exist
            cache.get(username);

            return new AuthenticatedUser(username);
        }
        catch (Exception e)
        {
            // the credentials were somehow invalid - either a non-existent role, or one without a defined password
            if (e.getCause() instanceof NoSuchRoleException)
                throw new AuthenticationException(String.format("Provided username %s is incorrect", username));

            // an unanticipated exception occured whilst querying the credentials table
            if (e.getCause() instanceof RequestExecutionException)
            {
                logger.trace("Error performing internal authentication", e);
                throw new AuthenticationException(String.format("Error during authentication of user %s : %s", username, e.getMessage()));
            }

            throw new RuntimeException(e);
        }
    }

    /**
     * Query Cassandra role table for a given role
     *
     * @param roleName Cassandra role name
     * @return role name
     */
    private String queryUserName(String roleName)
    {
        try
        {
            logger.debug("Querying role {}", roleName);

            ResultMessage.Rows rows =
                    getRoleStatement.execute(QueryState.forInternalCalls(),
                            QueryOptions.forInternalCalls(ConsistencyLevel.LOCAL_ONE,
                                    Lists.newArrayList(ByteBufferUtil.bytes(roleName))),
                            System.nanoTime());

            // If either a non-existent role name was supplied, or no credentials
            // were found for that role we don't want to cache the result so we throw
            // a specific, but unchecked, exception to keep LoadingCache happy.
            if (rows.result.isEmpty())
                throw new NoSuchRoleException();

            UntypedResultSet result = UntypedResultSet.create(rows.result);
            if (!result.one().has(ROLE))
                throw new NoSuchRoleException();

            return result.one().getString(ROLE);
        }
        catch (RequestExecutionException e)
        {
            logger.trace("Error performing internal authentication", e);
            throw e;
        }
    }

    private static class UserCache extends AuthCache<String, String> implements CredentialsCacheMBean
    {
        private UserCache(KerberosAuthenticator authenticator)
        {
            super("CredentialsCache",
                    DatabaseDescriptor::setCredentialsValidity,
                    DatabaseDescriptor::getCredentialsValidity,
                    DatabaseDescriptor::setCredentialsUpdateInterval,
                    DatabaseDescriptor::getCredentialsUpdateInterval,
                    DatabaseDescriptor::setCredentialsCacheMaxEntries,
                    DatabaseDescriptor::getCredentialsCacheMaxEntries,
                    authenticator::queryUserName,
                    () -> true);
        }

        public void invalidateCredentials(String roleName)
        {
            invalidate(roleName);
        }
    }

    public static interface CredentialsCacheMBean extends AuthCacheMBean
    {
        public void invalidateCredentials(String roleName);
    }

    // Just a marker so we can identify that invalid credentials were the
    // cause of a loading exception from the cache
    private static final class NoSuchRoleException extends RuntimeException
    {
    }
}
