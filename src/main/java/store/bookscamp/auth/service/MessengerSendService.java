package store.bookscamp.auth.service;

import java.util.List;
import java.util.Map;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class MessengerSendService {
    private static final String DOORAY_WEBHOOK_URL =
            "https://nhnacademy.dooray.com/services/3204376758577275363/4204662049267310806/TdCaWWnWSGyCfgckfa3TOQ";

    private final RestTemplate restTemplate = new RestTemplate();

    public String send(String randomNumber) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        Map<String, Object> body = Map.of(
                "botName", "BooksCamp 인증",
                "text", "인증을 통해 휴면상태 해제",
                "attachments", List.of(
                        Map.of(
                                "title", "아래의 번호를 화면에 입력해주세요",
                                "text", randomNumber,
                                "color", "RED"
                        )
                )
        );

        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(body, headers);

        ResponseEntity<String> response = restTemplate.postForEntity(
                DOORAY_WEBHOOK_URL,
                entity,
                String.class
        );

        return response.getBody();
    }
}
