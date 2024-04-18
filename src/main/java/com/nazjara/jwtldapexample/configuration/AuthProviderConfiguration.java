package com.nazjara.jwtldapexample.configuration;

import com.nazjara.jwtldapexample.mapper.CustomUserDetailsMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.ldap.core.support.DefaultTlsDirContextAuthenticationStrategy;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.ppolicy.PasswordPolicyAwareContextSource;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;

import java.util.Locale;

@Configuration
public class AuthProviderConfiguration {

    @Value("${security.ldap.url}")
    private String url;

    @Value("${security.ldap.tls.enabled}")
    private boolean tlsEnabled;

    @Value("${security.ldap.root-dn}")
    private String rootDn;

    @Value("${security.ldap.user-dn}")
    private String userDn;

    @Value("${security.ldap.password}")
    private String password;

    @Value("${security.ldap.user-search-filter}")
    private String userSearchFilter;

    @Value("${security.ldap.group-search-filter}")
    private String groupSearchFilter;

    @Bean
    @Primary
    public LdapContextSource contextSource() {
        var contextSource = new PasswordPolicyAwareContextSource(url);

        if (url.toLowerCase(Locale.ROOT).startsWith("ldap://") && tlsEnabled) {
            // this strategy enables startTls communication
            contextSource.setAuthenticationStrategy(new DefaultTlsDirContextAuthenticationStrategy());
        }

        contextSource.setUserDn(userDn);
        contextSource.setPassword(password);
        // is needed for tls shutdown on logout operation
        contextSource.setPooled(false);
        contextSource.afterPropertiesSet();

        return contextSource;
    }

    @Bean
    public LdapAuthenticationProvider ldapAuthenticationProvider(LdapContextSource contextSource) {
        var populator = new DefaultLdapAuthoritiesPopulator(contextSource, rootDn);
        populator.setGroupSearchFilter(groupSearchFilter);
        populator.setRolePrefix("");
        populator.setSearchSubtree(true);
        populator.setIgnorePartialResultException(true);
        populator.setConvertToUpperCase(false);

        var authenticator = new BindAuthenticator(contextSource);
        var userSearch = new FilterBasedLdapUserSearch(rootDn, userSearchFilter, contextSource);
        authenticator.setUserSearch(userSearch);

        var authenticationProvider = new LdapAuthenticationProvider(authenticator, populator);
        authenticationProvider.setUserDetailsContextMapper(new CustomUserDetailsMapper());
        return authenticationProvider;
    }
}
