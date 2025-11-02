package store.bookscamp.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import store.bookscamp.auth.entity.Member;
import store.bookscamp.auth.exception.MemberNotFoundException;
import store.bookscamp.auth.exception.WrongPasswordException;
import store.bookscamp.auth.repository.MemberCredentialRepository;
import store.bookscamp.auth.service.dto.MemberLoginDto;

@RequiredArgsConstructor
@Service
public class MemberLoginService {

    private final MemberCredentialRepository memberCredentialRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional(readOnly = true)
    public MemberLoginDto doLogin(MemberLoginDto memberLoginDto) {
        Member member = memberCredentialRepository.getByUsername(memberLoginDto.username()).orElseThrow(
                () -> new MemberNotFoundException("존재하지 않는 아이디입니다.")
        );

        if (!passwordEncoder.matches(memberLoginDto.password(), member.getPassword())) {
            throw new WrongPasswordException("비밀번호가 일치하지 않습니다.");
        }

        return MemberLoginDto.fromEntity(member);
    }
}
