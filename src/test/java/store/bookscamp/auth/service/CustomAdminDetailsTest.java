package store.bookscamp.auth.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.test.util.ReflectionTestUtils;
import store.bookscamp.auth.entity.Admin;

import java.util.Collection;

import static org.assertj.core.api.Assertions.assertThat;

class CustomAdminDetailsTest {

    @Test
    @DisplayName("Admin 엔티티의 정보를 올바르게 반환하는지 테스트")
    void getDetails() {
        Admin admin = new Admin("adminId", "adminPw");
        ReflectionTestUtils.setField(admin, "id", 99L);
        ReflectionTestUtils.setField(admin, "name", "최고관리자");

        CustomAdminDetails details = new CustomAdminDetails(admin);

        assertThat(details.getUsername()).isEqualTo("adminId");
        assertThat(details.getPassword()).isEqualTo("adminPw");
        assertThat(details.getId()).isEqualTo(99L);
        assertThat(details.getName()).isEqualTo("최고관리자");

        Collection<? extends GrantedAuthority> authorities = details.getAuthorities();
        assertThat(authorities).hasSize(1);
        assertThat(authorities.iterator().next().getAuthority()).isEqualTo("ADMIN");

        assertThat(details.isAccountNonExpired()).isTrue();
        assertThat(details.isAccountNonLocked()).isTrue();
        assertThat(details.isCredentialsNonExpired()).isTrue();
        assertThat(details.isEnabled()).isTrue();
    }
}