package com.rois.happy_shopping.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.concurrent.TimeUnit;

/**
 * 创建Redis分布式锁工具类，用于防止优惠券并发使用
 */
@Component
public class RedisLockUtil {

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    private static final String LOCK_PREFIX = "lock:";
    private static final String UNLOCK_SCRIPT = 
        "if redis.call('get', KEYS[1]) == ARGV[1] then " +
        "    return redis.call('del', KEYS[1]) " +
        "else " +
        "    return 0 " +
        "end";

    /**
     * 尝试获取锁
     * @param key 锁的key
     * @param value 锁的value（通常是线程标识）
     * @param expireTime 锁的过期时间（秒）
     * @return 是否获取成功
     */
    public boolean tryLock(String key, String value, long expireTime) {
        String lockKey = LOCK_PREFIX + key;
        Boolean result = redisTemplate.opsForValue().setIfAbsent(lockKey, value, expireTime, TimeUnit.SECONDS);
        return Boolean.TRUE.equals(result);
    }

    /**
     * 释放锁
     * @param key 锁的key
     * @param value 锁的value
     * @return 是否释放成功
     */
    public boolean unlock(String key, String value) {
        String lockKey = LOCK_PREFIX + key;
        DefaultRedisScript<Long> script = new DefaultRedisScript<>();
        script.setScriptText(UNLOCK_SCRIPT);
        script.setResultType(Long.class);
        
        Long result = redisTemplate.execute(script, Collections.singletonList(lockKey), value);
        return Long.valueOf(1).equals(result);
    }

    /**
     * 生成锁的唯一标识
     */
    public String generateLockValue() {
        return Thread.currentThread().getId() + ":" + System.currentTimeMillis();
    }
}
