package com.nazjara.jwtldapexample.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.ldap.userdetails.LdapUserDetails;

import java.util.Collection;

@AllArgsConstructor
@Getter
@Builder
public class LdapUser implements LdapUserDetails {
    private String dn;
    private String username;
    private String password;
    private String fullName;
    private String name;
    private String description;
    private Collection<? extends GrantedAuthority> authorities;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public String getDn() {
        return dn;
    }

    @Override
    public void eraseCredentials() {
        password = null;
    }
}
