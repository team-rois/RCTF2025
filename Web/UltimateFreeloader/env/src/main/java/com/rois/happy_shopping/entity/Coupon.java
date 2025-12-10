package com.rois.happy_shopping.entity;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * 创建Coupon优惠券实体类，包含优惠券信息和使用状态
 */
public class Coupon {
    private String id;
    private String userId;
    private String name;
    private BigDecimal discountAmount; // 优惠金额
    private Boolean isUsed; // 是否已使用
    private LocalDateTime expireTime; // 过期时间
    private LocalDateTime createTime;
    private LocalDateTime updateTime;

    public Coupon() {}

    /**
     * 构造函数，初始化优惠券信息
     * @param userId 用户ID
     * @param name 优惠券名称
     * @param discountAmount 优惠金额
     * @param expireTime 过期时间
     */
    public Coupon(String userId, String name, BigDecimal discountAmount, LocalDateTime expireTime) {
        this.id = UUID.randomUUID().toString();
        this.userId = userId;
        this.name = name;
        this.discountAmount = discountAmount;
        this.isUsed = false;
        this.expireTime = expireTime;
        this.createTime = LocalDateTime.now();
        this.updateTime = LocalDateTime.now();
    }

    // Getters and Setters
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public BigDecimal getDiscountAmount() {
        return discountAmount;
    }

    public void setDiscountAmount(BigDecimal discountAmount) {
        this.discountAmount = discountAmount;
    }

    public Boolean getIsUsed() {
        return isUsed;
    }

    public void setIsUsed(Boolean isUsed) {
        this.isUsed = isUsed;
    }

    public LocalDateTime getExpireTime() {
        return expireTime;
    }

    public void setExpireTime(LocalDateTime expireTime) {
        this.expireTime = expireTime;
    }

    public LocalDateTime getCreateTime() {
        return createTime;
    }

    public void setCreateTime(LocalDateTime createTime) {
        this.createTime = createTime;
    }

    public LocalDateTime getUpdateTime() {
        return updateTime;
    }

    public void setUpdateTime(LocalDateTime updateTime) {
        this.updateTime = updateTime;
    }
}
