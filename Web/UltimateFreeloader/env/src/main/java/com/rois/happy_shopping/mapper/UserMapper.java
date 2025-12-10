package com.rois.happy_shopping.mapper;

import com.rois.happy_shopping.entity.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

/**
 * 创建UserMapper接口，定义用户相关的数据库操作方法
 */
@Mapper
public interface UserMapper {
    /**
     * 插入用户
     */
    int insert(User user);
    
    /**
     * 根据用户名查找用户
     */
    User findByUsername(@Param("username") String username);
    
    /**
     * 根据ID查找用户
     */
    User findById(@Param("id") String id);
    
    /**
     * 更新用户余额
     */
    int updateBalance(@Param("id") String id, @Param("balance") java.math.BigDecimal balance);
    
    /**
     * 检查用户名是否存在
     */
    int countByUsername(@Param("username") String username);
    
    /**
     * 检查邮箱是否存在
     */
    int countByEmail(@Param("email") String email);
}
