# Cassandra Driver Authenticator

A GSSAPI authentication provider for [Apache Cassandra](https://cassandra.apache.org/).
This authenticator plugin is intended to work with the 
[Cassandra Java driver Kerberos authenticator](https://github.com/instaclustr/cassandra-java-driver-kerberos) 
plugin for the Apache [Cassandra Java driver](https://github.com/datastax/java-driver).

## Build

To build a fully-packaged JAR, just run `mvn clean package`

## Install

### Environment set-up

1. Ensure that the following pre-requisite systems are configured:
    
    - A unique DNS record is created for each node (use `hostname -f` on each node to verify that the DNS FQDN is configured)
    - A reverse DNS record is created for each node
    - A Kerberos 5 KDC server is available
    - Kerberos client libraries are installed on each Cassandra node
    - An NTP client is installed & configured on each Cassandra node. Ideally the Cassandra nodes sync 
      with the same time source as the KDC in order to minimise potential time-sync issues.
    - If using Oracle Java, ensure that the [Java Cryptographic Extensions Unlimited Strength Jurisdiction Policy Files](https://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html)
      are installed (not necessary when using OpenJDK or other JRE implementations)

2. Ensure that the value of [rpc_address](http://cassandra.apache.org/doc/latest/configuration/cassandra_config_file.html#rpc-address)
   (and optionally [broadcast_rpc_address](http://cassandra.apache.org/doc/latest/configuration/cassandra_config_file.html#broadcast-rpc-address), if using) 
   in the `cassandra.yaml` config file is not set to `localhost`

2. Configure the `/etc/krb5.conf` Kerberos config file on each node (see [here](http://web.mit.edu/kerberos/www/krb5-latest/doc/admin/conf_files/krb5_conf.html) for further details)

    ```
    [logging]
    default = FILE:/var/log/krb5libs.log
    
    [libdefaults]
     default_realm = EXAMPLE.COM
     dns_lookup_realm = false
     dns_lookup_kdc = false
    
    [realms]
     EXAMPLE.COM = {
      kdc = kdc.example.com
      admin_server = kdc.example.com
    }
    
    [domain_realm]
     .example.com = EXAMPLE.COM
     example.com = EXAMPLE.COM
    ```

3. For each cassandra node, create a new Kerberos service principal (see [here](http://web.mit.edu/kerberos/www/krb5-latest/doc/admin/admin_commands/kadmin_local.html#add-principal) for further details)

    ```
    kadmin -q "addprinc -randkey cassandra/node1.mycluster.example.com@EXAMPLE.COM"
    kadmin -q "addprinc -randkey cassandra/node2.mycluster.example.com@EXAMPLE.COM"
    kadmin -q "addprinc -randkey cassandra/node3.mycluster.example.com@EXAMPLE.COM"
    ```
    
    Note that the service name portion of the principal (`cassandra`, in this example) must be the same for 
    each node in the cluster, and must *also* match the SASL protocol name specified when configuring the 
    the [Cassandra Java driver Kerberos authenticator](https://github.com/instaclustr/cassandra-java-driver-kerberos).
    
    The hostname portion of the principal (e.g. `node1.mycluster.example.com`) must match the DNS entry for each Cassandra node.

4. Create a keytab for each newly created service principal (see [here](http://web.mit.edu/kerberos/www/krb5-latest/doc/admin/admin_commands/kadmin_local.html#ktadd) for further details)

    ```
    kadmin -q "ktadd -k /node1.keytab cassandra/node1.mycluster.example.com@EXAMPLE.COM"
    kadmin -q "ktadd -k /node2.keytab cassandra/node2.mycluster.example.com@EXAMPLE.COM"
    kadmin -q "ktadd -k /node3.keytab cassandra/node3.mycluster.example.com@EXAMPLE.COM"
    ```
    
5. Copy the corresponding keytab file to the Cassandra configuration directory on each node, 
   and set the appropriate access controls

    ```
    scp kdc.example.com:/node1.keytab /etc/cassandra/node1.keytab
    chown cassandra:cassandra /etc/cassandra/node1.keytab
    chmod 400 /etc/cassandra/node1.keytab
    ```

### Install & configure the Kerberos authenticator

1. Copy the `cassandra-krb5.properties` file to the Cassandra configuration directory on each node (e.g. `/etc/cassandra`). 
   Set `service_principal` and `keytab` to correspond to the service principals and keytabs created in the previous steps.

    ```
    service_principal=cassandra/node1.mycluster.example.com@EXAMPLE.COM
    keytab=node1.keytab
    qop=auth
    ```
    
2. Copy the authenicator jar to the Cassandra `lib` directory (e.g. `/usr/share/cassandra/lib/`)

3. Set the [authenticator](http://cassandra.apache.org/doc/latest/configuration/cassandra_config_file.html#authenticator)
   option in the `cassandra.yaml` config file.
   
    ```
    authenticator: com.instaclustr.cassandra.auth.KerberosAuthenticator
    ```
