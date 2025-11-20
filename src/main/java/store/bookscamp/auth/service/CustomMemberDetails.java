package store.bookscamp.auth.service;

import java.util.ArrayList;
import java.util.Collection;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import store.bookscamp.auth.entity.Member;
import store.bookscamp.auth.entity.MemberStatus;


public class CustomMemberDetails implements UserDetails {

    private final Member member;

    public CustomMemberDetails(Member member){
        this.member = member;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities(){
        Collection<GrantedAuthority> collection = new ArrayList<>();

        collection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return "USER";
            }
        });
        return collection;
    }
    @Override
    public String getPassword() {

        return member.getPassword();
    }

    public String getName() {return member.getName();}

    public Long getId(){
        return member.getId();
    }

    public Member getMember(){
        return this.member;
    }

    @Override
    public String getUsername() {

        return member.getUsername();
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

        return !member.getStatus().equals(MemberStatus.DORMANT);
    }
}
