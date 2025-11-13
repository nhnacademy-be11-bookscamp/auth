package store.bookscamp.auth.repository;

import java.util.concurrent.TimeUnit;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

@Repository
@RequiredArgsConstructor
public class RefreshTokenRepository {

    private final RedisTemplate<String, String> redisTemplate;

    public void save(String memberId, String refreshToken, long ttlMillis) {
        redisTemplate.opsForValue().set(
                memberId,
                refreshToken,
                ttlMillis,
                TimeUnit.MILLISECONDS
        );
    }

    public String findByMemberId(String memberId) {
        return redisTemplate.opsForValue().get(memberId);
    }
    public void deleteByMemberId(String memberId) {
        redisTemplate.delete(memberId);
    }
}