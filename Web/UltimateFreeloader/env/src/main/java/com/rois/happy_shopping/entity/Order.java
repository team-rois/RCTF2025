package com.rois.happy_shopping.entity;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

public class Order {
    private String id;
    private String userId;
    private String productId;
    private Integer quantity;
    private BigDecimal originalPrice; // 原价
    private BigDecimal discountAmount; // 优惠金额
    private BigDecimal finalPrice; // 最终价格
    private String couponId; // 使用的优惠券ID
    private String status; // 订单状态：PENDING, COMPLETED, CANCELLED
    private LocalDateTime createTime;
    private LocalDateTime updateTime;

    public Order() {}

    public Order(String userId, String productId, Integer quantity, BigDecimal originalPrice) {
        this.id = UUID.randomUUID().toString();
        this.userId = userId;
        this.productId = productId;
        this.quantity = quantity;
        this.originalPrice = originalPrice;
        this.discountAmount = BigDecimal.ZERO;
        this.finalPrice = originalPrice;
        this.status = "PENDING";
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

    public String getProductId() {
        return productId;
    }

    public void setProductId(String productId) {
        this.productId = productId;
    }

    public Integer getQuantity() {
        return quantity;
    }

    public void setQuantity(Integer quantity) {
        this.quantity = quantity;
    }

    public BigDecimal getOriginalPrice() {
        return originalPrice;
    }

    public void setOriginalPrice(BigDecimal originalPrice) {
        this.originalPrice = originalPrice;
    }

    public BigDecimal getDiscountAmount() {
        return discountAmount;
    }

    public void setDiscountAmount(BigDecimal discountAmount) {
        this.discountAmount = discountAmount;
    }

    public BigDecimal getFinalPrice() {
        return finalPrice;
    }

    public void setFinalPrice(BigDecimal finalPrice) {
        this.finalPrice = finalPrice;
    }

    public String getCouponId() {
        return couponId;
    }

    public void setCouponId(String couponId) {
        this.couponId = couponId;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
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
