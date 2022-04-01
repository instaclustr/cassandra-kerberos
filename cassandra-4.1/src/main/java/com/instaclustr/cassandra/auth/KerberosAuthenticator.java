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

import javax.security.sasl.Sasl;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;
import org.apache.cassandra.auth.AuthCache;
import org.apache.cassandra.auth.AuthCacheMBean;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.cql3.QueryOptions;
import org.apache.cassandra.cql3.QueryProcessor;
import org.apache.cassandra.cql3.statements.SelectStatement;
import org.apache.cassandra.db.ConsistencyLevel;
import org.apache.cassandra.service.ClientState;
import org.apache.cassandra.service.QueryState;
import org.apache.cassandra.transport.messages.ResultMessage.Rows;
import org.apache.cassandra.utils.ByteBufferUtil;
import org.apache.cassandra.utils.FBUtilities;

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
public class KerberosAuthenticator extends BaseKerberosAuthenticator
{
    private UserCache cache;

    @Override
    public void afterSetup()
    {
        cache = new UserCache(new QueryUserFunction()
        {
            @Override
            public SelectStatement prepare(final String query)
            {
                return (SelectStatement) QueryProcessor.getStatement(query, ClientState.forInternalCalls());
            }

            @Override
            public Rows execute(final String roleName)
            {
                return getRoleStatement.execute(QueryState.forInternalCalls(),
                                                QueryOptions.forInternalCalls(ConsistencyLevel.LOCAL_ONE,
                                                                              Lists.newArrayList(ByteBufferUtil.bytes(roleName))),
                                                System.nanoTime());
            }
        });
    }

    @Override
    public SaslNegotiator newSaslNegotiator(final InetAddress clientAddress)
    {
        final Configuration config = getConfiguration();
        final String saslProtocol = config.getKerberosPrincipalServiceNameComponent();
        final Map<String, String> saslProperties = ImmutableMap.<String, String>builder().put(Sasl.QOP, config.qop()).build();

        return new KerberosSaslAuthenticator(saslProtocol, saslProperties)
        {

            @Override
            public void fetchUser(final String username)
            {
                // This will throw an exception if the username does not exist
                cache.get(username);
            }

            @Override
            public String serverName() {
                return FBUtilities.getBroadcastAddressAndPort().getAddress().getCanonicalHostName();
            }
        };
    }


    public static class UserCache extends AuthCache<String, String> implements CredentialsCacheMBean
    {
        public UserCache(final QueryUserFunction queryUserFunction)
        {
            super("CredentialsCache",
                  DatabaseDescriptor::setCredentialsValidity,
                  DatabaseDescriptor::getCredentialsValidity,
                  DatabaseDescriptor::setCredentialsUpdateInterval,
                  DatabaseDescriptor::getCredentialsUpdateInterval,
                  DatabaseDescriptor::setCredentialsCacheMaxEntries,
                  DatabaseDescriptor::getCredentialsCacheMaxEntries,
                  DatabaseDescriptor::setCredentialsCacheActiveUpdate,
                  DatabaseDescriptor::getCredentialsCacheActiveUpdate,
                  queryUserFunction::apply,
                  HashMap::new,
                  () -> DatabaseDescriptor.getAuthenticator().requireAuthentication());
        }

        public void invalidateCredentials(final String roleName)
        {
            invalidate(roleName);
        }
    }

    public interface CredentialsCacheMBean extends AuthCacheMBean
    {
        void invalidateCredentials(final String roleName);
    }
}
