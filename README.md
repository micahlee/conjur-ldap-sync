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

    # Conjur server connection settings
    conjur-url: https://conjur.mycompany.net
    conjur-ca-cert-file: ./conjur-ca-cert.pem
    conjur-account: default
    conjur-username: admin
    conjur-password-file: ./conjur-password.txt

    # Sync configuration
    base-dn: dc=example,dc=org
    group-filter: (objectClass=posixGroup)
    user-filter: (objectClass=posixUser)
    policy-load-path: root
    ```

2. Store large and/or sensitive values in files:
    - `./ldap-ca-cert.pem`: LDAP server CA certificate
    - `./ldap-bind-password.txt`: LDAP bind password
    - `./conjur-ca-cert.pem`: Conjur server CA certificate
    - `./conjur-password.txt`: Conjur login password

3. Run LDAP sync with dry run

    Execute the command:

    ```sh
    conjur-ldap-sync --config-file="ldap-sync.yaml" --dry-run
    ```

4. View the generated policy documents in the `./policy` directory to inspect
   their contents.
  
5. Sync LDAP groups and users into Conjur

    Once satisfied with the outcome of the selected search filters and policy
    output, perform the sync by running `conjur-ldap-sync` without the `--dry-run`
    flag.

    ```sh
    conjur-ldap-sync --config-file="ldap-sync.yaml"
    ```

6. Verify groups and users exist in Conjur

### Command line interface (CLI)

The base `conjur-ldap-sync` command will connect to the configured LDAP server
to read the groups, users, and their memberships. It will then load these into
Conjur by loading generated policy documents.

The `--dry-run` run command causes `conjur-ldap-sync` to instead write the
resulting policy documents to files instead of attempting to load them in Conjur.

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
            User Filter <br>
            <code>user-filter</code>
         </td>
         <td>LDAP search filter used to identify LDAP users to sync.</td>
         <td><code>(objectClass=posixUser)</code></td>
      </tr>
      <tr>
         <td>
            Conjur Server URL <br>
            <code>conjur-url</code>
         </td>
         <td>URL to use when connecting to the Conjur server</td>
         <td><code>https://conjur.mycompany.net</code></td>
      </tr>
      <tr>
         <td>
            Conjur CA Certificate <br>
            <code>conjur-ca-cert-file</code>
         </td>
         <td>
         The PEM encoded, x.509 certificate to verify the Conjur server
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
            Conjur Account <br>
            <code>conjur-account</code>
         </td>
         <td>Conjur account to use.</td>
         <td><code>default</code></td>
      </tr>
      <tr>
         <td>
            Conjur LDAP Sync Base Policy <br>
            <code>policy-load-path</code>
         </td>
         <td>Conjur policy path to load groups and users into.</td>
         <td><code>root</code></td>
      </tr>
      <tr>
         <td>
            Conjur Username <br>
            <code>conjur-username</code>
         </td>
         <td>
            Username to authenticate to Conjur with. This user must have to load
            policy at the configured base policy path.
         </td>
         <td></td>
      </tr>
      <tr>
         <td>
            Conjur Password / API Key <br>
            <code>conjur-password-file</code>, <code>CONJUR_AUTHN_PASSWORD</code>*,
            <code>CONJUR_AUTHN_API_KEY</code>*
         </td>
         <td>
            Credentials to authenticate to Conjur with.
         </td>
         <td></td>
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
            Dry Run <br>
            <code>dry-run</code>
         </td>
         <td>
         Normally, <code>conjur-ldap-sync</code> loads generated group and user
         policy directly into Conjur. Configuring <code>dry-run</code> causes
         the policy files to be written as files under the `policy/` subdirectory
         instead of loading them into Conjur.
         </td>
         <td></td>
      </tr>
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
- As a Conjur policy object provided to the `conjur-ldap-sync` command with
  the `--config-resource` flag.

#### Command Line Arguments

Any arguments provided on the command line take precedence over values in
the config file or Conjur configuration resource.

Configuration parameters for sensitive values, such as the Conjur login password
and LDAP bind password cannot be provided directly as flag values, but may be
passed to the command as environment variables or file paths.

An example of using command line flags for all arguments is below. Note that
password values are provided as environment variables, not CLI flags.

```sh
conjur-ldap-sync \
   --conjur-appliance-url="https://conjur.my-company.local" \
   --conjur-ca-file="conjur-ca.pem" \
   --conjur-password-file="conjur-password.txt" \
   ...
```

#### Configuration YAML

```yaml
# ldap-sync.yml
conjur-appliance-url: https://conjur.my-company.local
conjur-ca-file: conjur-ca.pem
```

```sh
env 
   CONJUR_AUTHN_PASSWORD=$(<conjur_password_file) \
   LDAP_BIND_PASSWORD=$(<ldap_password_file) \
conjur-ldap-sync \
   --config-file="ldap-sync.yml"
```

#### Using Summon to provide password values

Reading environment variables can be combined with [summon](https://cyberark.github.io/summon/)
to provide the password values from the secure operating system store.

```yaml
# secrets.yml
CONJUR_AUTHN_PASSWORD: !var ldap-sync/conjur-password
LDAP_BIND_PASSWORD: !var ldap-sync/bind-password
```

```sh
summon -p keyring.py \
   conjur-ldap-sync --config-file="ldap-sync.yml"
```

#### Configuration in Conjur Policy

Configuring LDAP sync from a Conjur resource is provided to support backwards
compatibility with older entrprise LDAP sync configurations. To use this option,
you must have an existing policy `/conjur/ldap-sync` in Conjur with content
similar to:

```yaml
- !host
- !webservice
  owner: !host
- !group
  owner: !host

- !resource
  id: default
  owner: !host
  kind: configuration
  annotations:
    ldap-sync/base_dn: dc=example,dc=org
    ldap-sync/bind_dn: cn=admin,dc=example,dc=org
    ldap-sync/connect_type: tls
    ldap-sync/host: ldap-server
    ldap-sync/port: 389
    ldap-sync/group_attribute_mapping/name: cn
    ldap-sync/user_attribute_mapping/name: cn
    ldap-sync/group_filter: (objectClass=Group)
    ldap-sync/user_filter: (objectClass=User)
    
- !variable
  id: bind-password/default
  owner: !host

- !variable
  id: tls-ca-cert/default
  owner: !host
```

If so, Conjur LDAP sync can read these configuration values and use them to
connect to LDAP. In this case, only the Conjur configuration values are required.

```sh
env CONJUR_AUTHN_PASSWORD=$(<conjur_password_file) \
   conjur-ldap-sync \
      --conjur-appliance-url="https://conjur.my-company.local" \
      --conjur-ca-file="conjur-ca.pem" \
      --conjur-password-file="conjur-password.txt" \
      ...
      --config-resource="default"
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
