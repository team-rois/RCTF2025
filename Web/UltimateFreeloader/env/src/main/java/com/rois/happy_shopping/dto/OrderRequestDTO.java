package com.rois.happy_shopping.dto;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

public class OrderRequestDTO {
    @NotNull(message = "Order id cannot be empty")
    private String productId;
    @Size(max = 9, message = "Quantity is too large")
    @NotNull(message = "Quantity cannot be empty")
    private String quantity;
    
    private String couponId; // 优惠券ID，可选

    // Getters and Setters
    public String getProductId() {
        return productId;
    }

    public void setProductId(String productId) {
        this.productId = productId;
    }

    public String getQuantity() {
        return quantity;
    }

    public void setQuantity(String quantity) {
        this.quantity = quantity;
    }

    public String getCouponId() {
        return couponId;
    }

    public void setCouponId(String couponId) {
        this.couponId = couponId;
    }
}
