package store.bookscamp.auth.repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import store.bookscamp.auth.entity.Member;

public interface MemberCredentialRepository extends JpaRepository<Member,Long> {
    Optional<Member> getByUsername(String username);
}
