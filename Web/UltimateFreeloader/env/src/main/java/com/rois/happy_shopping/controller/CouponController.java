package com.rois.happy_shopping.controller;

import com.rois.happy_shopping.common.Result;
import com.rois.happy_shopping.entity.Coupon;
import com.rois.happy_shopping.service.CouponService;
import com.rois.happy_shopping.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@RestController
@RequestMapping("/api/coupon")
@CrossOrigin(origins = "*")
public class CouponController {

    @Autowired
    private CouponService couponService;

    @Autowired
    private JwtUtil jwtUtil;

    /**
     * Get user's available coupons
     */
    @GetMapping("/available")
    public Result<List<Coupon>> getAvailableCoupons(HttpServletRequest request) {
        String token = getTokenFromRequest(request);
        if (token == null || !jwtUtil.validateToken(token)) {
            return Result.error(401, "Unauthorized access");
        }

        String userId = jwtUtil.getUserIdFromToken(token);
        List<Coupon> coupons = couponService.getAvailableCoupons(userId);
        return Result.success("Get available coupons successfully", coupons);
    }

    /**
     * Get all user's coupons
     */
    @GetMapping("/my")
    public Result<List<Coupon>> getMyCoupons(HttpServletRequest request) {
        String token = getTokenFromRequest(request);
        if (token == null || !jwtUtil.validateToken(token)) {
            return Result.error(401, "Unauthorized access");
        }

        String userId = jwtUtil.getUserIdFromToken(token);
        List<Coupon> coupons = couponService.getUserCoupons(userId);
        return Result.success("Get my coupons successfully", coupons);
    }


    private String getTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
