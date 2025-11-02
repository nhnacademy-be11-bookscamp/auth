package store.bookscamp.auth.entity;

import static jakarta.persistence.EnumType.STRING;
import static jakarta.persistence.GenerationType.IDENTITY;
import static lombok.AccessLevel.PROTECTED;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import java.time.LocalDate;
import java.time.LocalDateTime;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;

@Entity
@Getter
@NoArgsConstructor(access = PROTECTED)
@SQLDelete(sql = "UPDATE `member` SET deleted_at = NOW() WHERE id = ?")
@SQLRestriction("deleted_at IS NULL")
public class Member  {

    @Id
    @GeneratedValue(strategy = IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false, unique = true)
    private String phone;

    @Column(nullable = false)
    private int point;

    @Enumerated(STRING)
    @Column(nullable = false)
    private MemberStatus status;

    @Column(nullable = false)
    private LocalDate statusUpdateDate;

    @Column(nullable = false, unique = true)
    private String username;

    private LocalDateTime lastLoginAt;

    @Column(nullable = false)
    private LocalDate birthDate;

    @Column(name = "deleted_at")
    private LocalDateTime deletedAt;

    public Member (String username,
                             String password){
        this.username = username;
        this.password = password;
    }
}
