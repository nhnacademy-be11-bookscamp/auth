package store.bookscamp.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import store.bookscamp.auth.entity.Member;
import store.bookscamp.auth.exception.MemberNotFoundException;
import store.bookscamp.auth.repository.MemberCredentialRepository;

@RequiredArgsConstructor
@Service
public class MemberLoginService implements UserDetailsService {

    private final MemberCredentialRepository memberCredentialRepository;

    @Override
    public UserDetails loadUserByUsername(String username){
        Member memberData = memberCredentialRepository.getByUsername(username).orElseThrow(
                () -> new MemberNotFoundException("존재하지 않는 아이디입니다.")
                );
        if(memberData != null){
            return new CustomMemberDetails(memberData);
        }
        return null;
    }

}
