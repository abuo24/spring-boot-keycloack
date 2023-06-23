//package uz.coder24.keycloack.config;
//
//import org.apache.juli.logging.Log;
//import org.apache.juli.logging.LogFactory;
//import org.springframework.core.convert.converter.Converter;
//import org.springframework.core.log.LogMessage;
//import org.springframework.security.authentication.AbstractAuthenticationToken;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.oauth2.jwt.Jwt;
//import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
//import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
//import org.springframework.util.Assert;
//import org.springframework.util.StringUtils;
//
//import java.util.*;
//import java.util.stream.Collectors;
//import java.util.stream.Stream;
//
//public class KeycloakRealmRolesGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
//    private String authorityPrefix = "";
//
//    public KeycloakRealmRolesGrantedAuthoritiesConverter() {
//    }
//
//    public KeycloakRealmRolesGrantedAuthoritiesConverter setAuthorityPrefix(String authorityPrefix) {
//        Assert.notNull(authorityPrefix, "authorityPrefix cannot be null");
//        this.authorityPrefix = authorityPrefix;
//        return this;
//    }
//
//    /**
//     * Get authorities from the {@code realm_access.roles} jwt claim
//     *
//     * @param source the source object to convert, which must be an instance of {@link Jwt} (never {@code null})
//     * @return collection of {@link GrantedAuthority}
//     */
//    @Override
//    public Collection<GrantedAuthority> convert(Jwt source) {
//        Map<String, Map<String, Object>> realmAccess = source.getClaim("resource_access");
//        if (Objects.isNull(realmAccess)) {
//            return Collections.emptySet();
//        }
//
//        Object roles = realmAccess.get("spring-boot").get("roles");
//        if (Objects.isNull(roles) || !Collection.class.isAssignableFrom(roles.getClass())) {
//            return Collections.emptySet();
//        }
//
//        var rolesCollection = (Collection<?>) roles;
//
//        return rolesCollection.stream()
//                .filter(String.class::isInstance) // The realm_access.role is supposed to be a list of string, for good measure we double-check that
//                .map(x -> new SimpleGrantedAuthority(authorityPrefix + x))
//                .collect(Collectors.toSet());
//    }
//
////
////    private final Log logger = LogFactory.getLog(getClass());
////
////    private static final String DEFAULT_AUTHORITY_PREFIX = "SCOPE_";
////
////    private static final String DEFAULT_AUTHORITIES_CLAIM_DELIMITER = " ";
////
////    private static final Collection<String> WELL_KNOWN_AUTHORITIES_CLAIM_NAMES = Arrays.asList("scope", "scp");
////
////    private String authorityPrefix = DEFAULT_AUTHORITY_PREFIX;
////
////    private String authoritiesClaimDelimiter = DEFAULT_AUTHORITIES_CLAIM_DELIMITER;
////
////    private String authoritiesClaimName;
////
////    /**
////     * Extract {@link GrantedAuthority}s from the given {@link Jwt}.
////     * @param jwt The {@link Jwt} token
////     * @return The {@link GrantedAuthority authorities} read from the token scopes
////     */
////    @Override
////    public Collection<GrantedAuthority> convert(Jwt jwt) {
////        Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
////        for (String authority : getAuthorities(jwt)) {
////            grantedAuthorities.add(new SimpleGrantedAuthority(this.authorityPrefix + authority));
////        }
////        return grantedAuthorities;
////    }
////
////    /**
////     * Sets the prefix to use for {@link GrantedAuthority authorities} mapped by this
////     * converter. Defaults to
////     * {@link org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter}.
////     * @param authorityPrefix The authority prefix
////     * @since 5.2
////     */
////    public void setAuthorityPrefix(String authorityPrefix) {
////        Assert.notNull(authorityPrefix, "authorityPrefix cannot be null");
////        this.authorityPrefix = authorityPrefix;
////    }
////
////    /**
////     * Sets the regex to use for splitting the value of the authorities claim into
////     * {@link GrantedAuthority authorities}. Defaults to
////     * @param authoritiesClaimDelimiter The regex used to split the authorities
////     * @since 6.1
////     */
////    public void setAuthoritiesClaimDelimiter(String authoritiesClaimDelimiter) {
////        Assert.notNull(authoritiesClaimDelimiter, "authoritiesClaimDelimiter cannot be null");
////        this.authoritiesClaimDelimiter = authoritiesClaimDelimiter;
////    }
////
////    /**
////     * Sets the name of token claim to use for mapping {@link GrantedAuthority
////     * authorities} by this converter. Defaults to
////     * @param authoritiesClaimName The token claim name to map authorities
////     * @since 5.2
////     */
////    public void setAuthoritiesClaimName(String authoritiesClaimName) {
////        Assert.hasText(authoritiesClaimName, "authoritiesClaimName cannot be empty");
////        this.authoritiesClaimName = authoritiesClaimName;
////    }
////
////    private String getAuthoritiesClaimName(Jwt jwt) {
////        if (this.authoritiesClaimName != null) {
////            return this.authoritiesClaimName;
////        }
////        for (String claimName : WELL_KNOWN_AUTHORITIES_CLAIM_NAMES) {
////            if (jwt.hasClaim(claimName)) {
////                return claimName;
////            }
////        }
////        return null;
////    }
////
////    private Collection<String> getAuthorities(Jwt jwt) {
////        String claimName = getAuthoritiesClaimName(jwt);
////        if (claimName == null) {
////            this.logger.trace("Returning no authorities since could not find any claims that might contain scopes");
////            return Collections.emptyList();
////        }
////        if (this.logger.isTraceEnabled()) {
////            this.logger.trace(LogMessage.format("Looking for scopes in claim %s", claimName));
////        }
////        Object authorities = jwt.getClaim(claimName);
////        if (authorities instanceof String) {
////            if (StringUtils.hasText((String) authorities)) {
////                return Arrays.asList(((String) authorities).split(this.authoritiesClaimDelimiter));
////            }
////            return Collections.emptyList();
////        }
////        if (authorities instanceof Collection) {
////            return castAuthoritiesToCollection(authorities);
////        }
////        return Collections.emptyList();
////    }
////
////    @SuppressWarnings("unchecked")
////    private Collection<String> castAuthoritiesToCollection(Object authorities) {
////        return (Collection<String>) authorities;
////    }
//
//
////    private List<String> clientIds;
////
////    @Override
////    public AbstractAuthenticationToken convert(Jwt source)
////    {
////        return new JwtAuthenticationToken(source, Stream.concat(new JwtGrantedAuthoritiesConverter().convert(source)
////                        .stream(), extractResourceRoles(source).stream())
////                .collect(Collectors.toSet()));
////    }
////
////    private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt)
////    {
////        var resourceAccess = new HashMap<>(jwt.getClaim("resource_access"));
////        var resourceRoles = new ArrayList<>();
////
////        clientIds.stream().forEach(id ->
////        {
////            if (resourceAccess.containsKey(id))
////            {
////                var resource = (Map<String, List<String>>) resourceAccess.get(id);
////                resource.get("roles").forEach(role -> resourceRoles.add(id + "_" + role));
////            }
////        });
////        return resourceRoles.isEmpty() ? Collections.emptySet() : resourceRoles.stream().map(r -> new SimpleGrantedAuthority("ROLE_" + r)).collect(Collectors.toSet());
////    }
//}