# custom-oidc-claim-handler

An OSGi bundle for WSO2 Identity Server that extends `DefaultOIDCClaimsCallbackHandler` so the `memberOf` claim in the
ID token **and** in JWT access tokens contains only group names instead of raw LDAP DN fragments:

```
Before: ["cn=group-01","ou=Groups","dc=example","dc=com", ...]
After:  ["group-01","group-02"]
```

The handler runs for every grant type, including the password grant, where adaptive authentication scripts do not
execute. Values that were already reduced (for example by an adaptive script) pass through unchanged.

## Compatibility

Built and tested against WSO2 Identity Server 5.11.0 (Java 8 runtime). The bundle is compiled with
`maven.compiler.release=8`. The dependency versions are set in the `pom.xml` properties.

## Build

Requires JDK 8+ and Maven 3.6+.

```bash
mvn clean package
```

The bundle is written to `target/custom-oidc-claim-handler-1.0.0.jar`. The WSO2 dependencies are resolved from the
public WSO2 Maven repository declared in the `pom.xml`.

## Deploy

1. Copy `target/custom-oidc-claim-handler-1.0.0.jar` to `<IS_HOME>/repository/components/dropins/`.

2. Register the handler in `<IS_HOME>/repository/conf/deployment.toml`:

   ```toml
   [oauth.oidc.extensions]
   claim_callback_handler = "org.wso2.custom.oidc.MemberOfClaimsCallbackHandler"
   ```

3. Create `<IS_HOME>/repository/conf/custom-oidc-claim-handler.properties` listing the OAuth client IDs (consumer keys)
   of the applications that should receive the reduced claim:

   ```properties
   memberof.clientIds=<client-id-1>,<client-id-2>
   ```

4. Restart the server.

## Behavior

- Only the claim named `memberOf` is modified, and only for the clients listed in the properties file. Tokens issued to
  every other client are unchanged.
- A missing or empty properties file means no client is affected.
- The properties file is re-read when it changes, so clients can be added or removed without a restart.
- Only `cn=` fragments are kept; `ou=` and `dc=` parts of the DN are dropped.
- The claim is split on commas that are not escaped with a backslash (RFC 4514), so a group name containing an escaped
  comma (`cn=a\,b`) stays a single group (`a,b`) rather than being split into extra groups.
- For JWT access tokens, `JWTTokenIssuer` builds the token from the `JWTClaimsSet.Builder` passed to the handler and
  ignores the claim set the handler returns. The handler therefore updates the builder as well as the returned set.

## Security considerations

- **Group names are no longer unique.** Only the `cn=` value is kept, so the `ou=`/`dc=` parts of the DN are lost. Two
  groups with the same name in different OUs or directories become indistinguishable. Do not use the reduced claim for
  authorization decisions unless group names are unique across your user stores.
- **Group names are trusted input.** The claim value is parsed as an LDAP DN string. If untrusted users can create or
  rename groups, make sure the directory escapes special characters (such as commas) in group names, and treat the
  reduced claim accordingly.
- The handler is applied only to the client IDs you list, which limits the impact to applications that expect
  group-name-only values.
