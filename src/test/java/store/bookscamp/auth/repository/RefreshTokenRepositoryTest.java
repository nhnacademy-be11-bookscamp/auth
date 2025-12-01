package store.bookscamp.auth.repository;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class RefreshTokenRepositoryTest {

    @Mock RedisTemplate<String, String> redisTemplate;
    @Mock ValueOperations<String, String> valueOperations;

    @InjectMocks RefreshTokenRepository refreshTokenRepository;

    @Test
    @DisplayName("Redis 저장 테스트")
    void save() {
        given(redisTemplate.opsForValue()).willReturn(valueOperations);

        refreshTokenRepository.save("key", "value", 1000L);

        verify(valueOperations).set("key", "value", 1000L, TimeUnit.MILLISECONDS);
    }

    @Test
    @DisplayName("Redis 조회 테스트")
    void findByMemberId() {
        given(redisTemplate.opsForValue()).willReturn(valueOperations);
        given(valueOperations.get("key")).willReturn("value");

        String result = refreshTokenRepository.findByMemberId("key");

        assertThat(result).isEqualTo("value");
    }
}