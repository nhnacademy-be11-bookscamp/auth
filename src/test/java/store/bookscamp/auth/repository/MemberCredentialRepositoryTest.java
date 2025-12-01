package store.bookscamp.auth.repository;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.util.ReflectionTestUtils;
import store.bookscamp.auth.entity.Member;
import store.bookscamp.auth.entity.MemberStatus;

import java.time.LocalDate;
import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
class MemberCredentialRepositoryTest {

    @Autowired MemberCredentialRepository memberCredentialRepository;

    @Test
    @DisplayName("휴면 계정 일괄 전환 쿼리 테스트")
    void updateStatusForOldLogins() {

        Member oldMember = new Member("old", "pw");
        ReflectionTestUtils.setField(oldMember, "status", MemberStatus.NORMAL);
        ReflectionTestUtils.setField(oldMember, "lastLoginAt", LocalDateTime.now().minusMonths(4));
        ReflectionTestUtils.setField(oldMember, "statusUpdateDate", LocalDate.now().minusMonths(4));
        ReflectionTestUtils.setField(oldMember, "name", "old");
        ReflectionTestUtils.setField(oldMember, "email", "old@test.com");
        ReflectionTestUtils.setField(oldMember, "phone", "010-0000-0000");
        ReflectionTestUtils.setField(oldMember, "point", 0);
        ReflectionTestUtils.setField(oldMember, "birthDate", LocalDate.now());

        memberCredentialRepository.save(oldMember);

        Member newMember = new Member("new", "pw");
        ReflectionTestUtils.setField(newMember, "status", MemberStatus.NORMAL);
        ReflectionTestUtils.setField(newMember, "lastLoginAt", LocalDateTime.now().minusMonths(1));
        ReflectionTestUtils.setField(newMember, "statusUpdateDate", LocalDate.now());
        ReflectionTestUtils.setField(newMember, "name", "new");
        ReflectionTestUtils.setField(newMember, "email", "new@test.com");
        ReflectionTestUtils.setField(newMember, "phone", "010-1111-1111");
        ReflectionTestUtils.setField(newMember, "point", 0);
        ReflectionTestUtils.setField(newMember, "birthDate", LocalDate.now());

        memberCredentialRepository.save(newMember);

        LocalDateTime cutoffDate = LocalDateTime.now().minusMonths(3);
        int updatedCount = memberCredentialRepository.updateStatusForOldLogins(
                MemberStatus.DORMANT,
                cutoffDate,
                LocalDate.now()
        );

        assertThat(updatedCount).isEqualTo(1);

        Member updatedOldMember = memberCredentialRepository.findById(oldMember.getId()).get();
        assertThat(updatedOldMember.getStatus()).isEqualTo(MemberStatus.DORMANT);
    }
}