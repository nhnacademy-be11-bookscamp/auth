package store.bookscamp.auth.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import store.bookscamp.auth.entity.MemberStatus;
import store.bookscamp.auth.repository.MemberCredentialRepository;

import java.time.LocalDate;
import java.time.LocalDateTime;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class MemberStatusSchedulerTest {

    @Mock
    private MemberCredentialRepository memberCredentialRepository;

    @InjectMocks
    private MemberStatusScheduler scheduler;

    @Test
    @DisplayName("휴면 계정 전환 스케줄러 실행 확인")
    void updateDormantMembers() {
        scheduler.updateDormantMembers();

        verify(memberCredentialRepository, times(1)).updateStatusForOldLogins(
                eq(MemberStatus.DORMANT),
                any(LocalDateTime.class),
                any(LocalDate.class)
        );
    }
}