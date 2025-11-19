package store.bookscamp.auth.repository;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import store.bookscamp.auth.entity.Member;
import store.bookscamp.auth.entity.MemberStatus;

public interface MemberCredentialRepository extends JpaRepository<Member,Long> {

    Optional<Member> getByUsername(String username);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE Member m SET m.status = :newStatus, m.statusUpdateDate = :updateDate WHERE m.lastLoginAt < :cutoffDate AND m.status <> :newStatus")
    int updateStatusForOldLogins(
            @Param("newStatus") MemberStatus newStatus,
            @Param("cutoffDate") LocalDateTime cutoffDate,
            @Param("updateDate") LocalDate updateDate
    );
}
