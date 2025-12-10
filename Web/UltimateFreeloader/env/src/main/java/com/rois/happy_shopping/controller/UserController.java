package com.rois.happy_shopping.controller;

import com.rois.happy_shopping.common.Result;
import com.rois.happy_shopping.dto.UserLoginDTO;
import com.rois.happy_shopping.dto.UserRegisterDTO;
import com.rois.happy_shopping.entity.User;
import com.rois.happy_shopping.service.UserService;
import com.rois.happy_shopping.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.Map;

@RestController
@RequestMapping("/api/user")
@CrossOrigin(origins = "*")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/register")
    public Result<?> register(@Valid @RequestBody UserRegisterDTO registerDTO) {
        Map<String, Object> result = userService.register(registerDTO);
        
        if ((Boolean) result.get("success")) {
            return Result.success("Registration successful", result);
        } else {
            return Result.error((String) result.get("message"));
        }
    }

    @PostMapping("/login")
    public Result<?> login(@Valid @RequestBody UserLoginDTO loginDTO) {
        Map<String, Object> result = userService.login(loginDTO);
        
        if ((Boolean) result.get("success")) {
            return Result.success("Login successful", result);
        } else {
            return Result.error((String) result.get("message"));
        }
    }

    @GetMapping("/info")
    public Result<User> getUserInfo(HttpServletRequest request) {
        String token = getTokenFromRequest(request);
        if (token == null || !jwtUtil.validateToken(token)) {
            return Result.error(401, "Unauthorized access");
        }

        String userId = jwtUtil.getUserIdFromToken(token);
        User user = userService.findById(userId);
        
        if (user != null) {
            // Don't return password
            user.setPassword(null);
            return Result.success(user);
        } else {
            return Result.error("User not found");
        }
    }

    private String getTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
