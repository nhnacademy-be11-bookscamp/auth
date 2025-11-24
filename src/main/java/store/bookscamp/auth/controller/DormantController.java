package store.bookscamp.auth.controller;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j; // 로그 사용을 위해 추가
import org.springframework.data.redis.core.StringRedisTemplate; // 변경됨
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import store.bookscamp.auth.service.MemberLoginService;
import store.bookscamp.auth.service.MessengerSendService;

@Slf4j // 롬복 로그 어노테이션 추가
@RequiredArgsConstructor
@RequestMapping("/dormant")
@RestController
public class DormantController {

    private final MemberLoginService memberLoginService;
    private final MessengerSendService messengerSendService;

    // [수정 1] RedisTemplate<String, String> -> StringRedisTemplate 으로 변경 (안전성 확보)
    private final StringRedisTemplate redisTemplate;

    private static final Duration AUTH_CODE_TTL = Duration.ofSeconds(300);
    private static final String REDIS_KEY_PREFIX = "dormant:auth:";

    @PostMapping("/send")
    public ResponseEntity<Map<String, Object>> sendDormantCode(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        log.info("휴면 해제 요청 받음: {}", username); // 로그 1

        if (username == null) {
            return ResponseEntity.badRequest().body(Map.of("message", "사용자 이름이 필요합니다."));
        }

        String randomNumber = String.valueOf((int) (Math.random() * 900000) + 100000);
        String redisKey = REDIS_KEY_PREFIX + username;

        try {
            // 1. Redis 저장
            redisTemplate.opsForValue().set(redisKey, randomNumber, AUTH_CODE_TTL);
            log.info("Redis 저장 완료: {}", redisKey); // 로그 2

            // 2. 메신저 발송
            messengerSendService.send(randomNumber);
            log.info("메신저 발송 완료"); // 로그 3

            // 3. 성공 응답 생성
            Map<String, Object> response = new HashMap<>();
            response.put("message", "인증번호가 성공적으로 발송되었습니다.");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            // [중요] 에러 발생 시 서버 로그에 빨간색으로 출력하여 원인 파악
            log.error("휴면 해제 프로세스 중 오류 발생", e);

            return ResponseEntity.status(500).body(Map.of("message", "서버 내부 오류: " + e.getMessage()));
        }
    }

    @PostMapping("/verify")
    public ResponseEntity<Map<String, String>> verifyDormantCode(@RequestBody Map<String, String> request) {
        // (검증 로직은 기존과 동일하되, StringRedisTemplate 메서드만 사용하면 됩니다)
        String username = request.get("username");
        String code = request.get("code");

        if (username == null || code == null) {
            return ResponseEntity.badRequest().body(Map.of("message", "정보가 부족합니다."));
        }

        String redisKey = REDIS_KEY_PREFIX + username;
        String storedCode = redisTemplate.opsForValue().get(redisKey);

        if (storedCode == null) {
            return ResponseEntity.status(400).body(Map.of("message", "인증번호가 만료되었습니다."));
        }

        if (!storedCode.equals(code)) {
            return ResponseEntity.status(400).body(Map.of("message", "인증번호가 일치하지 않습니다."));
        }

        memberLoginService.activateDormantMember(username);
        redisTemplate.delete(redisKey);

        return ResponseEntity.ok(Map.of("message", "휴면 해제 성공"));
    }
}