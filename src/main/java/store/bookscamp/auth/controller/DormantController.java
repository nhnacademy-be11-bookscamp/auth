package store.bookscamp.auth.controller;

import java.time.Duration;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import store.bookscamp.auth.service.MemberLoginService;
import store.bookscamp.auth.service.MessengerSendService;

@RequiredArgsConstructor
@RequestMapping("/dormant")
@RestController
public class DormantController {

    private final MemberLoginService memberLoginService;
    private final MessengerSendService messengerSendService;
    private final RedisTemplate<String, String> redisTemplate;
    private static final Duration AUTH_CODE_TTL = Duration.ofSeconds(300);
    private static final String REDIS_KEY_PREFIX = "dormant:auth:";

    @PostMapping("/send")
    public ResponseEntity<Map<String, String>> sendDormantCode(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        if (username == null) {
            return ResponseEntity.badRequest().body(Map.of("message", "사용자 이름이 필요합니다."));
        }

        String randomNumber = String.valueOf((int) (Math.random() * 900000) + 100000);
        String redisKey = REDIS_KEY_PREFIX + username;

        try {
            redisTemplate.opsForValue().set(redisKey, randomNumber, AUTH_CODE_TTL);

            messengerSendService.send(randomNumber);

            return ResponseEntity.ok(Map.of("message", "인증번호가 성공적으로 발송되었습니다."));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("message", "인증번호 발송/저장에 실패했습니다."));
        }
    }

    @PostMapping("/verify")
    public ResponseEntity<Map<String, String>> verifyDormantCode(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String code = request.get("code");

        if (username == null || code == null) {
            return ResponseEntity.badRequest().body(Map.of("message", "사용자 이름과 인증번호가 필요합니다."));
        }

        String redisKey = REDIS_KEY_PREFIX + username;
        String storedCode = redisTemplate.opsForValue().get(redisKey);

        if (storedCode == null) {
            return ResponseEntity.status(400).body(Map.of("message", "인증번호가 만료되었거나 발송되지 않았습니다."));
        }

        if (!storedCode.equals(code)) {
            return ResponseEntity.status(400).body(Map.of("message", "인증번호가 일치하지 않습니다."));
        }

        memberLoginService.activateDormantMember(username);

        redisTemplate.delete(redisKey);

        return ResponseEntity.ok(Map.of("message", "휴면 상태가 성공적으로 해제되었습니다."));
    }
}
