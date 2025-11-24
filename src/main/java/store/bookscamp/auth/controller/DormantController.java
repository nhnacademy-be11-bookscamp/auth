package store.bookscamp.auth.controller;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import store.bookscamp.auth.service.MemberLoginService;
import store.bookscamp.auth.service.MessengerSendService;

@Slf4j
@RequiredArgsConstructor
@RequestMapping("/dormant")
@RestController
public class DormantController {

    private final MemberLoginService memberLoginService;
    private final MessengerSendService messengerSendService;
    private final StringRedisTemplate redisTemplate;

    private static final Duration AUTH_CODE_TTL = Duration.ofSeconds(300);
    private static final String REDIS_KEY_PREFIX = "dormant:auth:";

    @PostMapping("/send")
    public ResponseEntity<Map<String, Object>> sendDormantCode(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        log.info("1. 요청 진입: {}", username);

        if (username == null) {
            return ResponseEntity.badRequest().body(Map.of("message", "사용자 이름이 필요합니다."));
        }

        String randomNumber = String.valueOf((int) (Math.random() * 900000) + 100000);
        String redisKey = REDIS_KEY_PREFIX + username;

        try {
            redisTemplate.opsForValue().set(redisKey, randomNumber, AUTH_CODE_TTL);
            messengerSendService.send(randomNumber);

            log.info("2. 로직 완료, 응답 생성 시작");

            Map<String, Object> responseMap = new HashMap<>();
            responseMap.put("message", "인증번호가 발송되었습니다.");
            responseMap.put("status", "success");

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            log.info("3. 응답 리턴 직전");
            return new ResponseEntity<>(responseMap, headers, org.springframework.http.HttpStatus.OK);

        } catch (Exception e) {
            log.error("에러 발생", e);
            return ResponseEntity.status(500).body(Map.of("message", "서버 에러: " + e.getMessage()));
        }
    }

    @PostMapping("/verify")
    public ResponseEntity<Map<String, Object>> verifyDormantCode(@RequestBody Map<String, String> request) {
        
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

        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("message", "휴면 해제 성공");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        return new ResponseEntity<>(responseMap, headers, org.springframework.http.HttpStatus.OK);
    }
}
