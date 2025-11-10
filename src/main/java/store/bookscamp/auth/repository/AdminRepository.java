package store.bookscamp.auth.repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import store.bookscamp.auth.entity.Admin;

public interface AdminRepository extends JpaRepository<Admin,Long> {
    Optional<Admin> getByUsername(String username);
}
