package store.bookscamp.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import store.bookscamp.auth.entity.Admin;
import store.bookscamp.auth.exception.MemberNotFoundException;
import store.bookscamp.auth.repository.AdminRepository;


@RequiredArgsConstructor
@Service
public class AdminLoginService implements UserDetailsService {

    private final AdminRepository adminRepository;

    @Override
    public UserDetails loadUserByUsername(String username){
        Admin adminData = adminRepository.getByUsername(username).orElseThrow(
                () -> new MemberNotFoundException("존재하지 않는 아이디입니다.")
        );
        if(adminData != null){
            return new CustomAdminDetails(adminData);
        }
        return null;
    }

}
