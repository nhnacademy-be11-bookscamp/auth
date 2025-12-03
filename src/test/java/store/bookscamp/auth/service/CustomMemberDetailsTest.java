package store.bookscamp.auth.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import store.bookscamp.auth.entity.Member;
import store.bookscamp.auth.entity.MemberStatus;

import static org.assertj.core.api.Assertions.assertThat;

class CustomMemberDetailsTest {

    @Test
    @DisplayName("Member 객체 정보를 정상적으로 반환해야 한다 (모든 Getter 및 UserDetails 메서드 검증)")
    void fullCoverage_Check() {
        Member member = new Member("user", "pw");
        ReflectionTestUtils.setField(member, "id", 100L);
        ReflectionTestUtils.setField(member, "name", "HongGilDong");
        ReflectionTestUtils.setField(member, "status", MemberStatus.NORMAL);

        CustomMemberDetails details = new CustomMemberDetails(member);

        assertThat(details.getUsername()).isEqualTo("user");
        assertThat(details.getPassword()).isEqualTo("pw");
        assertThat(details.getName()).isEqualTo("HongGilDong");
        assertThat(details.getId()).isEqualTo(100L);
        assertThat(details.getMember()).isEqualTo(member);

        assertThat(details.getAuthorities()).hasSize(1);
        assertThat(details.getAuthorities().iterator().next().getAuthority()).isEqualTo("USER");

        assertThat(details.isAccountNonExpired()).isTrue();
        assertThat(details.isAccountNonLocked()).isTrue();
        assertThat(details.isCredentialsNonExpired()).isTrue();

        assertThat(details.isEnabled()).isTrue();
    }

    @Test
    @DisplayName("휴면 계정(DORMANT)인 경우 isEnabled는 false를 반환해야 한다")
    void isEnabled_Dormant_Check() {
        Member dormantMember = new Member("dormant", "pw");
        ReflectionTestUtils.setField(dormantMember, "status", MemberStatus.DORMANT);
        CustomMemberDetails dormantDetails = new CustomMemberDetails(dormantMember);

        assertThat(dormantDetails.isEnabled()).isFalse();
    }
}