package store.bookscamp.auth.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.util.ReflectionTestUtils;
import store.bookscamp.auth.entity.Admin;
import store.bookscamp.auth.exception.MemberNotFoundException;
import store.bookscamp.auth.repository.AdminRepository;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
class AdminLoginServiceTest {

    @Mock
    private AdminRepository adminRepository;

    @InjectMocks
    private AdminLoginService adminLoginService;

    @Test
    @DisplayName("loadUserByUsername 성공: Admin 객체를 찾아 UserDetails로 반환한다")
    void loadUserByUsername_Success() {
        String username = "adminUser";
        String password = "adminPassword";

        Admin admin = new Admin(username, password);
        ReflectionTestUtils.setField(admin, "id", 1L);
        ReflectionTestUtils.setField(admin, "name", "관리자");

        given(adminRepository.getByUsername(username)).willReturn(Optional.of(admin));

        UserDetails userDetails = adminLoginService.loadUserByUsername(username);

        assertThat(userDetails).isNotNull();
        assertThat(userDetails).isInstanceOf(CustomAdminDetails.class);
        assertThat(userDetails.getUsername()).isEqualTo(username);

        CustomAdminDetails customDetails = (CustomAdminDetails) userDetails;
        assertThat(customDetails.getName()).isEqualTo("관리자");
    }


    @Test
    @DisplayName("loadUserByUsername 실패: 존재하지 않는 아이디면 예외 발생")
    void loadUserByUsername_Fail() {
        String username = "unknownAdmin";
        given(adminRepository.getByUsername(username)).willReturn(Optional.empty());

        assertThatThrownBy(() -> adminLoginService.loadUserByUsername(username))
                .isInstanceOf(MemberNotFoundException.class)
                .hasMessage("존재하지 않는 아이디입니다.");
    }
}