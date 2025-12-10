package com.rois.happy_shopping.dto;

import javax.validation.constraints.NotBlank;

/**
 * 创建用户登录DTO类
 */
public class UserLoginDTO {
    @NotBlank(message = "username cannot be empty")
    private String username;
    
    @NotBlank(message = "password cannot be empty")
    private String password;

    // Getters and Setters
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
