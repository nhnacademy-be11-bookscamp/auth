package store.bookscamp.auth.service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import store.bookscamp.auth.entity.MemberStatus; // MemberStatus enum import
import store.bookscamp.auth.repository.MemberCredentialRepository;

@Slf4j
@Component
@RequiredArgsConstructor
public class MemberStatusScheduler {

    private final MemberCredentialRepository memberCredentialRepository;

    @Scheduled(cron = "0 0 0 * * *")
    @Transactional
    public void updateDormantMembers() {
        log.info("[스케줄러] 휴면 계정 전환 작업을 시작합니다.");

        try {
            LocalDateTime cutoffDate = LocalDateTime.now().minusMonths(3);

            int updatedCount = memberCredentialRepository.updateStatusForOldLogins(
                    MemberStatus.DORMANT,
                    cutoffDate,
                    LocalDate.now()
            );

            if (updatedCount > 0) {
                log.info("[스케줄러] 총 {}명의 회원을 휴면 상태로 전환했습니다.", updatedCount);
            } else {
                log.info("[스케줄러] 휴면 상태로 전환할 회원이 없습니다.");
            }

        } catch (Exception e) {
            log.error("[스케줄러] 휴면 계정 전환 작업 중 오류가 발생했습니다.", e);
        }
    }
}