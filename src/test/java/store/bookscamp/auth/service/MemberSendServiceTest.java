package store.bookscamp.auth.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
class MessengerSendServiceTest {

    @InjectMocks
    private MessengerSendService messengerSendService;

    @Mock
    private RestTemplate restTemplate;

    @Test
    @DisplayName("메신저 전송 성공")
    void send_Success() {

        ReflectionTestUtils.setField(messengerSendService, "restTemplate", restTemplate);

        String randomNumber = "123456";
        String expectedResponse = "{\"result\":\"ok\"}";

        given(restTemplate.postForEntity(any(String.class), any(HttpEntity.class), eq(String.class)))
                .willReturn(ResponseEntity.ok(expectedResponse));

        String result = messengerSendService.send(randomNumber);

        assertThat(result).isEqualTo(expectedResponse);
    }
}