package org.wso2.custom.oidc;

import com.nimbusds.jwt.JWTClaimsSet;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.openidconnect.DefaultOIDCClaimsCallbackHandler;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Extends the default OIDC claims callback handler so that the {@code memberOf} claim in the ID token and in JWT access tokens carries only
 * the group names, e.g. {@code ["cn=group-01","ou=Groups","dc=wso2","dc=com"]} becomes {@code ["group-01"]}.
 * Applies to every grant type, including the password grant where adaptive authentication scripts do not run.
 * <p>
 * The reduction is applied only to the OAuth clients (service providers) whose client IDs are listed in
 * {@code <IS_HOME>/repository/conf/custom-oidc-claim-handler.properties}:
 * <pre>
 * memberof.clientIds=clientIdOfApp1,clientIdOfApp2
 * </pre>
 * Tokens issued to any other client are left exactly as the default handler produced them. If the file is missing or
 * the property is empty, no client is affected. The file is re-read when it changes, so no restart is needed to
 * add or remove a client.
 */
public class MemberOfClaimsCallbackHandler extends DefaultOIDCClaimsCallbackHandler {

    static final String MEMBER_OF_CLAIM = "memberOf";
    private static final String CN_PREFIX = "cn=";
    private static final String MULTI_VALUE_SEPARATOR = ",";
    private static final String CONFIG_FILE = "custom-oidc-claim-handler.properties";
    private static final String CLIENT_IDS_PROPERTY = "memberof.clientIds";
    private static final Logger LOG = Logger.getLogger(MemberOfClaimsCallbackHandler.class.getName());

    private volatile Set<String> enabledClientIds = Collections.emptySet();
    private volatile long configLastModified = -1;

    @Override
    public JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder builder, OAuthTokenReqMessageContext requestMsgCtx)
            throws IdentityOAuth2Exception {

        JWTClaimsSet claims = super.handleCustomClaims(builder, requestMsgCtx);
        String clientId = requestMsgCtx.getOauth2AccessTokenReqDTO().getClientId();
        return isEnabledFor(clientId) ? reduceMemberOfToGroupNames(builder, claims) : claims;
    }

    @Override
    public JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder builder, OAuthAuthzReqMessageContext requestMsgCtx)
            throws IdentityOAuth2Exception {

        JWTClaimsSet claims = super.handleCustomClaims(builder, requestMsgCtx);
        String clientId = requestMsgCtx.getAuthorizationReqDTO().getConsumerKey();
        return isEnabledFor(clientId) ? reduceMemberOfToGroupNames(builder, claims) : claims;
    }

    private boolean isEnabledFor(String clientId) {

        return clientId != null && loadEnabledClientIds().contains(clientId);
    }

    /** Returns the configured client IDs, reloading the properties file only when it has changed. */
    private Set<String> loadEnabledClientIds() {

        File file = new File(System.getProperty("carbon.home"), "repository/conf/" + CONFIG_FILE);
        long modified = file.exists() ? file.lastModified() : 0;
        if (modified != configLastModified) {
            synchronized (this) {
                if (modified != configLastModified) {
                    Set<String> ids = new HashSet<>();
                    if (modified > 0) {
                        Properties properties = new Properties();
                        try (InputStream in = new FileInputStream(file)) {
                            properties.load(in);
                            for (String id : properties.getProperty(CLIENT_IDS_PROPERTY, "")
                                    .split(MULTI_VALUE_SEPARATOR)) {
                                if (!id.trim().isEmpty()) {
                                    ids.add(id.trim());
                                }
                            }
                        } catch (IOException e) {
                            LOG.log(Level.WARNING, "Unable to read " + file + "; memberOf will not be reduced.", e);
                        }
                    }
                    enabledClientIds = ids;
                    configLastModified = modified;
                }
            }
        }
        return enabledClientIds;
    }

    /**
     * The builder is updated as well as the returned claim set: the ID token path uses the returned set, but the JWT
     * access token path (JWTTokenIssuer) builds the final token from the builder and ignores the returned value.
     */
    private JWTClaimsSet reduceMemberOfToGroupNames(JWTClaimsSet.Builder builder, JWTClaimsSet claims) {

        if (claims == null) {
            return null;
        }
        Object memberOf = claims.getClaim(MEMBER_OF_CLAIM);
        if (memberOf == null) {
            return claims;
        }
        List<String> groupNames = toGroupNames(memberOf);
        builder.claim(MEMBER_OF_CLAIM, groupNames);
        return new JWTClaimsSet.Builder(claims).claim(MEMBER_OF_CLAIM, groupNames).build();
    }

    /**
     * Converts the raw claim value (a comma separated string, or a collection/array of DN fragments) to group names.
     * Only {@code cn=} fragments are kept, so {@code ou=} and {@code dc=} parts of the DN are dropped. A value that
     * has already been reduced (no {@code name=value} fragments, e.g. by an adaptive script) is returned unchanged.
     */
    static List<String> toGroupNames(Object value) {

        List<String> fragments = new ArrayList<>();
        collect(value, fragments);

        boolean hasDnFragments = fragments.stream().anyMatch(f -> f.indexOf('=') > 0);
        List<String> names = new ArrayList<>();
        for (String fragment : fragments) {
            if (!hasDnFragments) {
                names.add(fragment);
            } else if (fragment.toLowerCase(Locale.ROOT).startsWith(CN_PREFIX)) {
                names.add(fragment.substring(CN_PREFIX.length()));
            }
        }
        return names;
    }

    private static void collect(Object value, List<String> fragments) {

        if (value instanceof Collection) {
            for (Object item : (Collection<?>) value) {
                collect(item, fragments);
            }
        } else if (value instanceof Object[]) {
            for (Object item : (Object[]) value) {
                collect(item, fragments);
            }
        } else if (value != null) {
            for (String part : value.toString().split(MULTI_VALUE_SEPARATOR)) {
                String trimmed = part.trim();
                if (!trimmed.isEmpty()) {
                    fragments.add(trimmed);
                }
            }
        }
    }
}
