# CyberArk Conjur LDAP Sync

Conjur LDAP sync synchronizes users and groups from an LDAP directory (e.g.
Microsoft Active Directory) into Conjur. Once loaded into Conjur, LDAP users
can [authenticate with the Conjur API using their LDAP credentials](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Integrations/ldap/ldap_authenticator.html),
and LDAP groups may be used to grant secrets access permissions.

## Certification level

![](https://img.shields.io/badge/Certification%20Level-Community-28A745?link=https://github.com/cyberark/community/blob/master/Conjur/conventions/certification-levels.md)

This repo is a **Community** level project. It's a community contributed project that **is not reviewed or supported
by CyberArk**. For more detailed information on our certification levels, see [our community guidelines](https://github.com/cyberark/community/blob/master/Conjur/conventions/certification-levels.md#community).

## Requirements

- An LDAP server (such as Microsoft Active Directory)
- LDAP credentials authorized to view the resources to sync to Conjur
- A Conjur server (OSS or Enterprise)
- Conjur credentials authorized to load root policy

## Usage instructions

### Quick start

1. Create a configuration file to connect to the LDAP and Conjur services.

    ```yaml
    # ./ldap-sync.yaml

    # LDAP server connection settings
    ldap-host: ldap-server.mycompany.net
    ldap-port: 389
    connection-type: tls
    ldap-ca-cert-file: ./ldap-ca-cert.pem
    bind-dn: cn=admin,dc=example,dc=org
    bind-password-file: ./ldap-bind-password.txt

    # Sync configuration
    base-dn: dc=example,dc=org
    group-filter: (objectClass=posixGroup)
    group-name-attribute: cn
    user-filter: (objectClass=posixUser)
    user-name-attribute: uid
    ```

    *NOTE:* If you are migrating from the legacy DAP LDAP Sync, you may view
    the values for most of these values by running the command:

    ```sh
    conjur show <my-account>:configuration:conjur/ldap-sync/default
    ```

2. Store large and/or sensitive values in files:
    - `./ldap-ca-cert.pem`: LDAP server CA certificate
    - `./ldap-bind-password.txt`: LDAP bind password

3. Run LDAP sync to display the policy

    Execute the command:

    ```sh
    conjur-ldap-sync policy show
    ```

    *NOTE:* The default configuration filename is `./ldap-sync.yaml`. If your
    configuration file is named something else or located in another directory,
    specify the path to it with the `--config-file` flag. For example:

    ```sh
    conjur-ldap-sync policy show --config-file="my-ldap-sync-config.yaml"
    ```

4. Sync LDAP groups and users into Conjur

    Once satisfied with the outcome of the selected search filters and policy
    output, perform the sync by loading the generated policy in Conjur

    ```sh-session
    $ conjur-ldap-sync policy show | tee policies/ldap.yaml
    ...
    $ conjur policy load root policies/ldap.yaml
    ```

5. Verify groups and users exist in Conjur

    This may be accomplished by running:

    ```sh
    conjur list
    ```

### Command line interface (CLI)

The base `conjur-ldap-sync` command will connect to the configured LDAP server
to read the groups, users, and memberships. It then generates the Conjur
policy to define these Users and Groups so they can be used in secrets
management policy.

### Windows service

Conjur LDAP sync can be run periodically as a Windows services...

> TODO: Review and include how this is accomplished now in
> [conjur-host-automation](https://github.com/aharriscybr/conjur-host-automation/blob/main/hosts/powershell/main.ps1#L604-L633)

### Cron job

Conjur LDAP sync can be run periodically as a Linux cron job...
### Configuration

Running LDAP Sync will require you to have the following configuration
values available.

*NOTE:* Names with '\*' denotes the environment variable version.

<table>
   <thead>
      <tr>
         <th>Name</th>
         <th>Description</th>
         <th>Example</th>
      </tr>
   </thead>
   <tbody>
      <tr>
         <td>
            Bind Distinguished Name (DN) <br>
            <code>bind-dn</code>
         </td>
         <td>The username DN to use when authenticating with the LDAP server.</td>
         <td><code>cn=admin,dc=example,dc=org</code></td>
      </tr>
      <tr>
         <td>
            Bind Password <br>
            <code>bind-password-file</code>, <code>LDAP_BIND_PASSWORD</code>*
         </td>
         <td>The password to use when authenticating with the LDAP server.</td>
         <td></td>
      </tr>
      <tr>
         <td>
            LDAP Server Connection Type <br>
            <code>connection-type</code>
         </td>
         <td>
         The type of network connection to use. Valid options are
         <ul>
            <li><code>tls</code>: Connect using LDAP over TLS (StartTLS).</li>
            <li><code>ssl</code>: Connect using LDAPS.</li>
            <li><code>plain</code>: Connect using unsecured TCP. (Not recommended)</li>
         </ul>
         </td>
         <td><code>tls</code></td>
      </tr>
      <tr>
         <td>
            LDAP Server Certificate Authority (CA) Certificate <br>
            <code>ldap-ca-cert-file</code>
         </td>
         <td>
         The PEM encoded, x.509 certificate to verify the LDAP server
         connection with.
         </td>
         <td>
            <pre style="white-space: pre">
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----</pre>
         </td>
      </tr>
      <tr>
         <td>
            LDAP Server Host <br>
            <code>ldap-host</code>
         </td>
         <td>Hostname to use for the LDAP connection.</td>
         <td><code>ldap-server.mycompany.net</code></td>
      </tr>
      <tr>
         <td>
            LDAP Server Port <br>
            <code>ldap-port</code>
         </td>
         <td>
            TCP port to use for the LDAP connection. Common values are <code>389</code>
            for <code>tls</code> and <code>plain</code> connections, and
            <code>636</code> for <code>ssl</code> connections.
         </td> 
         <td><code>389</code></td>
      </tr>
      <tr>
         <td>
            Base DN <br>
            <code>base-dn</code>
         </td>
         <td>
         The name of root LDAP object on which to base user and group searches.
         </td>
         <td><code>dc=example,dc=org</code></td>
      </tr>
      <tr>
         <td>
            Group Filter <br>
            <code>group-filter</code>
         </td>
         <td>LDAP search filter used to identify LDAP groups to sync.</td>
         <td><code>(objectClass=posixGroup)</code></td>
      </tr>
      <tr>
         <td>
            Group Name Attribute <br>
            <code>group-name-attribute</code>
         </td>
         <td>LDAP attribute to use for the group name in Conjur.</td>
         <td><code>cn</code></td>
      </tr>
      <tr>
         <td>
            User Filter <br>
            <code>user-filter</code>
         </td>
         <td>LDAP search filter used to identify LDAP users to sync.</td>
         <td><code>(objectClass=posixUser)</code></td>
      </tr>
      <tr>
         <td>
            User Name Attribute <br>
            <code>user-name-attribute</code>
         </td>
         <td>LDAP attribute to use for the group name in Conjur.</td>
         <td><code>cn</code></td>
      </tr>
   </tbody>
</table>

Configuration values available to control the behavior of `conjur-ldap-sync` are:

<table>
   <thead>
      <tr>
         <th>Name</th>
         <th>Description</th>
         <th>Example</th>
      </tr>
   </thead>
   <tbody>
      <tr>
         <td>
            Sync Batch Size <br>
            <code>sync-batch-size</code>
         </td>
         <td>
         By default, <code>conjur-ldap-sync</code> reads up to 1000 records at a
         time from the LDAP server and generates the policy for them. This value
         can be changed using the <code>sync-batch-size</code> configuration.
         </td>
         <td><code>1000</code></td>
      </tr>
   </tbody>
</table>

LDAP sync parameters can be provided in one of three ways:

- As individual configuration flags on the `conjur-ldap-sync` command.
- As a YAML configuration file provided to the `conjur-ldap-sync` command with
  the `--config-file` flag.

#### Command Line Arguments

Any arguments provided on the command line take precedence over values in
the config file or Conjur configuration resource.

Configuration parameters for sensitive values, such as the LDAP bind password
cannot be provided directly as flag values, but may be passed to the command as
environment variables or file paths.

An example of using command line flags for all arguments is below. Note that
password values are provided as environment variables, not CLI flags.

```sh
conjur-ldap-sync policy show \
   --bind-password-file="ldap-password.txt" \
   ...
```

#### Configuration YAML

```yaml
# ldap-sync.yml
# LDAP server connection settings
    ldap-host: ldap-server.mycompany.net
    ldap-port: 389
    connection-type: tls
    ldap-ca-cert-file: ./ldap-ca-cert.pem
    bind-dn: cn=admin,dc=example,dc=org
    bind-password-file: ./ldap-bind-password.txt

    # Sync configuration
    base-dn: dc=example,dc=org
    group-filter: (objectClass=posixGroup)
    group-name-attribute: cn
    user-filter: (objectClass=posixUser)
    user-name-attribute: uid
```

```sh
env 
   LDAP_BIND_PASSWORD=$(<ldap_password_file) \
conjur-ldap-sync policy show \
   --config-file="ldap-sync.yml"
```

#### Using Summon to provide password values

Reading environment variables can be combined with [summon](https://cyberark.github.io/summon/)
to provide the password values from the secure operating system store.

```yaml
# secrets.yml
LDAP_BIND_PASSWORD: !var ldap-sync/bind-password
```

```sh
summon -p keyring.py \
   conjur-ldap-sync policy show
```

### Policy Templates

Conjur LDAP Sync uses templates to generate the policy entries for users and
groups for LDAP.

These templates may be customized, for example, to use a different LDAP
attribute for the user or group names in Conjur. Templates use the
[golang template syntax](https://golang.org/pkg/text/template/).

`conjur-ldap-sync` loads the policy templates from the `./templates` subdirectory,
 if they exist:

- `user.yaml.tmpl` - The template for an individual user resource.
- `group.yaml.tmpl` - The template for an individual group resource.
- `membership.yaml.tmpl` - The template for an individual membership grants.

To create the initial template files with their default values, run the command:

```sh
conjur-ldap-sync export-templates
```

These may then be edited to customize the policy output.

To revert back to the default behavior, either delete the custom template files
or run the above command again to replace the custom templates with the default.

#### Default User Policy Template

```golang
{{ define "user" -}}
# {{ .DN }}
- !user
  id: {{ .GetAttributeValue "uid" }}
  annotations:
    ldap-sync: true
    description: Created by Conjur LDAP sync automation
{{ end -}}
```

#### Default Group Policy Template

```golang
{{ define "group" -}}
# {{ .DN }}
- !group
  id: {{ .GetAttributeValue "cn" }}
  annotations:
    ldap-sync: true
    description: Created by Conjur LDAP sync automation
{{ end -}}
```

#### Default Membership Policy Template

```golang
{{ define "membership" -}}
{{end -}}
```

## Contributing

We welcome contributions of all kinds to this repository. For instructions on how to get started and descriptions
of our development workflows, please see our [contributing guide](CONTRIBUTING.md).

## License

Copyright (c) 2020 CyberArk Software Ltd. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

For the full license text see [`LICENSE`](LICENSE).
