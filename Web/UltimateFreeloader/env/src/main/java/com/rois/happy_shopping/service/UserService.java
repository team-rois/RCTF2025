package com.rois.happy_shopping.service;

import com.rois.happy_shopping.dto.UserLoginDTO;
import com.rois.happy_shopping.dto.UserRegisterDTO;
import com.rois.happy_shopping.entity.Coupon;
import com.rois.happy_shopping.entity.User;
import com.rois.happy_shopping.mapper.CouponMapper;
import com.rois.happy_shopping.mapper.UserMapper;
import com.rois.happy_shopping.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Service
public class UserService {

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private CouponMapper couponMapper;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    /**
     * User registration
     */
    @Transactional
    public Map<String, Object> register(UserRegisterDTO registerDTO) {
        Map<String, Object> result = new HashMap<>();

        // Check if username already exists
        if (userMapper.countByUsername(registerDTO.getUsername()) > 0) {
            result.put("success", false);
            result.put("message", "Username already exists");
            return result;
        }

        // Check if email already exists
        if (userMapper.countByEmail(registerDTO.getEmail()) > 0) {
            result.put("success", false);
            result.put("message", "Email already registered");
            return result;
        }

        // Create user
        User user = new User(
            registerDTO.getUsername(),
            passwordEncoder.encode(registerDTO.getPassword()),
            registerDTO.getEmail()
        );

        // Save user
        userMapper.insert(user);

        // Create welcome coupon for new user
        Coupon welcomeCoupon = new Coupon(
            user.getId(),
            "Welcome Coupon",
            new BigDecimal("10.00"),
            LocalDateTime.now().plusDays(30) // 30 days validity
        );
        couponMapper.insert(welcomeCoupon);

        // Generate JWT token
        String token = jwtUtil.generateToken(user.getUsername(), user.getId());

        result.put("success", true);
        result.put("message", "Registration successful");
        result.put("token", token);
        result.put("user", user);
        return result;
    }

    /**
     * User login
     */
    public Map<String, Object> login(UserLoginDTO loginDTO) {
        Map<String, Object> result = new HashMap<>();

        // Find user
        User user = userMapper.findByUsername(loginDTO.getUsername());
        if (user == null) {
            result.put("success", false);
            result.put("message", "Invalid username or password");
            return result;
        }

        // Verify password
        if (!passwordEncoder.matches(loginDTO.getPassword(), user.getPassword())) {
            result.put("success", false);
            result.put("message", "Invalid username or password");
            return result;
        }

        // Generate JWT token
        String token = jwtUtil.generateToken(user.getUsername(), user.getId());

        result.put("success", true);
        result.put("message", "Login successful");
        result.put("token", token);
        result.put("user", user);
        return result;
    }

    /**
     * Find user by ID
     */
    public User findById(String id) {
        return userMapper.findById(id);
    }

    /**
     * Update user balance
     */
    public boolean updateBalance(String userId, BigDecimal balance) {
        return userMapper.updateBalance(userId, balance) > 0;
    }
}
