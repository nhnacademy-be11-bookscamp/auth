package store.bookscamp.auth.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.util.ReflectionTestUtils;
import store.bookscamp.auth.entity.Member;
import store.bookscamp.auth.entity.MemberStatus;
import store.bookscamp.auth.exception.MemberNotFoundException;
import store.bookscamp.auth.repository.MemberCredentialRepository;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class MemberLoginServiceTest {

    @Mock
    private MemberCredentialRepository memberCredentialRepository;

    @InjectMocks
    private MemberLoginService memberLoginService;

    @Test
    @DisplayName("loadUserByUsername 성공: 회원이 존재하면 UserDetails를 반환한다")
    void loadUserByUsername_Success() {
        String username = "bookscampUser";
        String password = "securePassword";

        Member member = new Member(username, password);

        ReflectionTestUtils.setField(member, "id", 1L);
        ReflectionTestUtils.setField(member, "name", "홍길동");
        ReflectionTestUtils.setField(member, "status", MemberStatus.NORMAL);

        given(memberCredentialRepository.getByUsername(username)).willReturn(Optional.of(member));

        UserDetails userDetails = memberLoginService.loadUserByUsername(username);

        assertThat(userDetails).isNotNull();
        assertThat(userDetails).isInstanceOf(CustomMemberDetails.class);
        assertThat(userDetails.getUsername()).isEqualTo(username);

        CustomMemberDetails details = (CustomMemberDetails) userDetails;
        assertThat(details.getMember().getName()).isEqualTo("홍길동");
    }

    @Test
    @DisplayName("loadUserByUsername 실패: 회원이 없으면 MemberNotFoundException 발생")
    void loadUserByUsername_Fail_NotFound() {
        String username = "unknownUser";
        given(memberCredentialRepository.getByUsername(username)).willReturn(Optional.empty());

        assertThatThrownBy(() -> memberLoginService.loadUserByUsername(username))
                .isInstanceOf(MemberNotFoundException.class)
                .hasMessage("존재하지 않는 아이디입니다.");
    }

    @Test
    @DisplayName("activateDormantMember 성공: 휴면 회원을 조회하여 상태를 NORMAL로 변경하고 저장한다")
    void activateDormantMember_Success() {
        String username = "dormantUser";
        Member member = new Member(username, "pw");

        ReflectionTestUtils.setField(member, "status", MemberStatus.DORMANT);
        ReflectionTestUtils.setField(member, "id", 2L);

        given(memberCredentialRepository.getByUsername(username)).willReturn(Optional.of(member));

        memberLoginService.activateDormantMember(username);

        assertThat(member.getStatus()).isEqualTo(MemberStatus.NORMAL);

        verify(memberCredentialRepository, times(1)).save(member);
    }

    @Test
    @DisplayName("activateDormantMember 실패: 회원이 없으면 예외 발생 및 저장하지 않음")
    void activateDormantMember_Fail() {
        String username = "ghostUser";
        given(memberCredentialRepository.getByUsername(username)).willReturn(Optional.empty());

        assertThatThrownBy(() -> memberLoginService.activateDormantMember(username))
                .isInstanceOf(MemberNotFoundException.class);

        verify(memberCredentialRepository, times(0)).save(any());
    }
}