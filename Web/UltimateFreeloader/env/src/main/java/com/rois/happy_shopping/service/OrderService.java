package com.rois.happy_shopping.service;

import com.rois.happy_shopping.dto.OrderRequestDTO;
import com.rois.happy_shopping.entity.Coupon;
import com.rois.happy_shopping.entity.Order;
import com.rois.happy_shopping.entity.Product;
import com.rois.happy_shopping.entity.User;
import com.rois.happy_shopping.mapper.OrderMapper;
import com.rois.happy_shopping.util.RedisLockUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class OrderService {

    @Autowired
    private OrderMapper orderMapper;

    @Autowired
    private UserService userService;

    @Autowired
    private ProductService productService;

    @Autowired
    private CouponService couponService;

    @Autowired
    private RedisLockUtil redisLockUtil;


    /**
     * Create order
     */
    @Transactional
    public Map<String, Object> createOrder(String userId, OrderRequestDTO orderRequest) {
        Map<String, Object> result = new HashMap<>();
        String lockKey = "order:user:" + userId;
        String lockValue = redisLockUtil.generateLockValue();

        if (!redisLockUtil.tryLock(lockKey, lockValue, 3)) {
            result.put("success", false);
            result.put("message", "System is busy, please try again later");
            return result;
        }

        try {
            // Validate user
            User user = userService.findById(userId);
            if (user == null) {
                result.put("success", false);
                result.put("message", "User not found");
                return result;
            }


            // Validate product
            Product product = productService.getProductById(orderRequest.getProductId());
            if (product == null) {
                result.put("success", false);
                result.put("message", "Product not found");
                return result;
            }


            // Handle coupon
            BigDecimal discountAmount = BigDecimal.ZERO;
            String couponId = null;
            if (orderRequest.getCouponId() != null) {
                if (!couponService.validateCoupon(orderRequest.getCouponId(), userId)) {
                    result.put("success", false);
                    result.put("message", "Coupon is not available");
                    return result;
                }
                Coupon coupon = couponService.getCouponById(orderRequest.getCouponId());
                discountAmount = coupon.getDiscountAmount();
                couponId = coupon.getId();
            }

            // Calculate original price
            Integer quantityNum;
            BigDecimal unitPrice = product.getPrice();
            BigDecimal quantity = new BigDecimal(orderRequest.getQuantity());
            if (quantity.compareTo(BigDecimal.ZERO) <= 0){
                result.put("success", false);
                result.put("message", "Quantity must be greater than zero");
                return result;
            }

            BigDecimal compare = quantity.subtract(new BigDecimal("100"));
            if (compare.compareTo(BigDecimal.ZERO) > 0){
                quantityNum = 1;
                quantity = new BigDecimal(quantityNum);
            }else {
                quantityNum = Integer.parseInt(orderRequest.getQuantity());
            }

            System.out.println(quantityNum);
            BigDecimal originalPrice = unitPrice.multiply(quantity).setScale(2, RoundingMode.HALF_UP);

            // Calculate final price
            BigDecimal finalPrice = originalPrice.subtract(discountAmount);
            if (finalPrice.compareTo(BigDecimal.ZERO) < 0) {
                finalPrice = BigDecimal.ZERO;
            }
            finalPrice = finalPrice.setScale(2, RoundingMode.HALF_UP);

            // Check user balance
            if (user.getBalance().compareTo(finalPrice) < 0) {
                result.put("success", false);
                result.put("message", "Insufficient balance");
                return result;
            }

            // Create order
            Order order = new Order(userId, orderRequest.getProductId(), quantityNum, originalPrice);
            order.setDiscountAmount(discountAmount);
            order.setFinalPrice(finalPrice);
            order.setCouponId(couponId);
            orderMapper.insert(order);

            // Deduct user balance
            BigDecimal newBalance = user.getBalance().subtract(finalPrice);
            if (!userService.updateBalance(userId, newBalance)) {
                throw new RuntimeException("Failed to deduct balance");
            }

            // Use coupon
            if (couponId != null) {
                if (!couponService.useCoupon(couponId)) {
                    throw new RuntimeException("Failed to use coupon");
                }
            }

            // Update order status to completed
            orderMapper.updateStatus(order.getId(), "COMPLETED");

            result.put("success", true);
            result.put("message", "Order created successfully");
            result.put("order", order);
            result.put("remainingBalance", newBalance);
            return result;

        } catch (Exception e) {
            result.put("success", false);
            result.put("message", "Order creation failed: " + e.getMessage());
            return result;
        } finally {
            redisLockUtil.unlock(lockKey, lockValue);
        }
    }

    /**
     * Get user order list
     */
    public List<Order> getUserOrders(String userId) {
        return orderMapper.findByUserId(userId);
    }

    /**
     * Get order by ID
     */
    public Order getOrderById(String id) {
        return orderMapper.findById(id);
    }

    /**
     * Order refund
     */
    @Transactional
    public Map<String, Object> refundOrder(String orderId, String userId) {
        Map<String, Object> result = new HashMap<>();
        String lockKey = "refund:order:" + orderId;
        String lockValue = redisLockUtil.generateLockValue();

        // Try to acquire Redis lock, 5 seconds validity
        if (!redisLockUtil.tryLock(lockKey, lockValue, 5)) {
            result.put("success", false);
            result.put("message", "System is busy, please try again later");
            return result;
        }

        try {
            // 1. Validate order exists
            Order order = orderMapper.findById(orderId);
            if (order == null) {
                result.put("success", false);
                result.put("message", "Order not found");
                return result;
            }

            // 2. Validate order belongs to current user
            if (!order.getUserId().equals(userId)) {
                result.put("success", false);
                result.put("message", "No permission to operate this order");
                return result;
            }

            // 3. Validate order status (only completed orders can be refunded)
            if (!"COMPLETED".equals(order.getStatus())) {
                result.put("success", false);
                result.put("message", "This order status does not support refund");
                return result;
            }

            // 4. Get user information
            User user = userService.findById(userId);
            if (user == null) {
                result.put("success", false);
                result.put("message", "User not found");
                return result;
            }

            // 5. Restore user balance
            BigDecimal newBalance = user.getBalance().add(order.getFinalPrice());
            if (!userService.updateBalance(userId, newBalance)) {
                throw new RuntimeException("Failed to restore user balance");
            }

            // 6. Restore coupon status (if coupon was used)
            if (order.getCouponId() != null) {
                if (!couponService.restoreCoupon(order.getCouponId())) {
                    throw new RuntimeException("Failed to restore coupon");
                }
            }

            // 7. Update order status to refunded
            if (!updateOrderStatus(orderId, "REFUNDED")) {
                throw new RuntimeException("Failed to update order status");
            }

            result.put("success", true);
            result.put("message", "Refund successful");
            result.put("refundAmount", order.getFinalPrice());
            result.put("newBalance", newBalance);
            return result;

        } catch (Exception e) {
            result.put("success", false);
            result.put("message", "Refund failed: " + e.getMessage());
            return result;
        } finally {
            // Release lock
            redisLockUtil.unlock(lockKey, lockValue);
        }
    }

    /**
     * Update order status
     */
    private boolean updateOrderStatus(String orderId, String status) {
        return orderMapper.updateStatus(orderId, status) > 0;
    }
}
