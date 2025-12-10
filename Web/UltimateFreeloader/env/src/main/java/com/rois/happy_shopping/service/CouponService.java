package com.rois.happy_shopping.service;

import com.rois.happy_shopping.entity.Coupon;
import com.rois.happy_shopping.mapper.CouponMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 创建CouponService服务类，处理优惠券相关的业务逻辑
 */
@Service
public class CouponService {

    @Autowired
    private CouponMapper couponMapper;

    /**
     * 获取用户可用的优惠券
     */
    public List<Coupon> getAvailableCoupons(String userId) {
        return couponMapper.findAvailableByUserId(userId);
    }

    /**
     * 根据ID获取优惠券
     */
    public Coupon getCouponById(String id) {
        return couponMapper.findById(id);
    }

    /**
     * 验证优惠券是否可用
     */
    public boolean validateCoupon(String couponId, String userId) {
        Coupon coupon = couponMapper.findById(couponId);
        if (coupon == null) {
            return false;
        }
        // 检查是否属于该用户
        if (!coupon.getUserId().equals(userId)) {
            return false;
        }
        // 检查是否已使用
        if (coupon.getIsUsed()) {
            return false;
        }
        // 检查是否过期
        if (coupon.getExpireTime().isBefore(LocalDateTime.now())) {
            return false;
        }
        return true;
    }

    /**
     * 使用优惠券
     */
    public boolean useCoupon(String couponId) {
        return couponMapper.updateUsedStatus(couponId, true) > 0;
    }

    /**
     * 恢复优惠券状态（退款时使用）
     */
    public boolean restoreCoupon(String couponId) {
        return couponMapper.updateUsedStatus(couponId, false) > 0;
    }

    /**
     * 获取用户所有优惠券
     */
    public List<Coupon> getUserCoupons(String userId) {
        return couponMapper.findByUserId(userId);
    }
}
