package store.bookscamp.auth.service;

import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import store.bookscamp.auth.entity.Member;
import store.bookscamp.auth.entity.MemberStatus;

import static org.assertj.core.api.Assertions.assertThat;

class CustomMemberDetailsTest {

    @Test
    void isEnabled_Check() {
        Member normalMember = new Member("user", "pw");
        ReflectionTestUtils.setField(normalMember, "status", MemberStatus.NORMAL);

        Member dormantMember = new Member("dormant", "pw");
        ReflectionTestUtils.setField(dormantMember, "status", MemberStatus.DORMANT);

        CustomMemberDetails normalDetails = new CustomMemberDetails(normalMember);
        CustomMemberDetails dormantDetails = new CustomMemberDetails(dormantMember);

        assertThat(normalDetails.isEnabled()).isTrue();
        assertThat(dormantDetails.isEnabled()).isFalse();

        assertThat(normalDetails.getUsername()).isEqualTo("user");
        assertThat(normalDetails.getPassword()).isEqualTo("pw");
        assertThat(normalDetails.isAccountNonExpired()).isTrue();
    }
}