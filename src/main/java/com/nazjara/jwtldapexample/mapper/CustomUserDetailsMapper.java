package com.nazjara.jwtldapexample.mapper;

import com.nazjara.jwtldapexample.model.LdapUser;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.ldap.userdetails.LdapUserDetails;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;

import java.util.Collection;

public class CustomUserDetailsMapper extends LdapUserDetailsMapper {
    @Override
    public LdapUser mapUserFromContext(DirContextOperations ctx, String username,
                                       Collection<? extends GrantedAuthority> authorities) {
        var userDetails = (LdapUserDetails) super.mapUserFromContext(ctx, username, authorities);

        return LdapUser.builder()
                .dn(userDetails.getDn())
                .username(userDetails.getUsername())
                .password(userDetails.getPassword())
                .authorities(userDetails.getAuthorities())
                .name(ctx.getStringAttribute("sn"))
                .fullName(ctx.getStringAttribute("cn"))
                .description(ctx.getStringAttribute("description"))
                .build();
    }
}
