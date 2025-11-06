package store.bookscamp.auth.common.filter;

import java.util.ArrayList;
import java.util.Collection;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class AuthUser implements UserDetails {

    private final Long memberId;
    private final String role;

    public AuthUser(Long memberId, String role){
        this.memberId = memberId;
        this.role = role;
    }

    public Long getMemberId() {
        return memberId;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities(){
        Collection<GrantedAuthority> authorities = new ArrayList<>();

        authorities.add(() -> role);
        return authorities;
    }

    @Override
    public String getUsername() {
        return memberId.toString();
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public boolean isAccountNonExpired() { return true; }

    @Override
    public boolean isAccountNonLocked() { return true; }

    @Override
    public boolean isCredentialsNonExpired() { return true; }

    @Override
    public boolean isEnabled() { return true; }
}