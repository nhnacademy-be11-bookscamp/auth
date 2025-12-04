package store.bookscamp.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import store.bookscamp.auth.service.MemberLoginService;
import store.bookscamp.auth.service.MessengerSendService;

import java.time.Duration;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(DormantController.class)
class DormantControllerTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;

    @MockitoBean MemberLoginService memberLoginService;
    @MockitoBean MessengerSendService messengerSendService;
    @MockitoBean StringRedisTemplate redisTemplate;
    @MockitoBean ValueOperations<String, String> valueOperations;

    @Test
    @DisplayName("인증번호 발송 성공")
    @WithMockUser
    void sendDormantCode_Success() throws Exception {
        Map<String, String> request = Map.of("username", "testuser");

        given(redisTemplate.opsForValue()).willReturn(valueOperations);

        mockMvc.perform(post("/dormant/send")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("success"));

        verify(messengerSendService).send(any());
        verify(valueOperations).set(eq("dormant:auth:testuser"), any(), any(Duration.class));
    }

    @Test
    @DisplayName("인증번호 검증 성공: 휴면 해제")
    @WithMockUser
    void verifyDormantCode_Success() throws Exception {
        String username = "testuser";
        String code = "123456";
        Map<String, String> request = Map.of("username", username, "code", code);

        given(redisTemplate.opsForValue()).willReturn(valueOperations);
        given(valueOperations.get("dormant:auth:" + username)).willReturn(code);

        mockMvc.perform(post("/dormant/verify")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("휴면 해제 성공"));

        verify(memberLoginService).activateDormantMember(username);
        verify(redisTemplate).delete("dormant:auth:" + username);
    }

    @Test
    @DisplayName("인증번호 검증 실패: 불일치")
    @WithMockUser
    void verifyDormantCode_Fail_Mismatch() throws Exception {
        String username = "testuser";
        Map<String, String> request = Map.of("username", username, "code", "999999");

        given(redisTemplate.opsForValue()).willReturn(valueOperations);
        given(valueOperations.get("dormant:auth:" + username)).willReturn("123456");

        mockMvc.perform(post("/dormant/verify")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("인증번호가 일치하지 않습니다."));
    }
}