package com.rois.happy_shopping.mapper;

import com.rois.happy_shopping.entity.Order;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/**
 * 创建OrderMapper接口，定义订单相关的数据库操作方法
 */
@Mapper
public interface OrderMapper {
    /**
     * 插入订单
     */
    int insert(Order order);
    
    /**
     * 根据ID查找订单
     */
    Order findById(@Param("id") String id);
    
    /**
     * 查找用户的所有订单
     */
    List<Order> findByUserId(@Param("userId") String userId);
    
    /**
     * 更新订单状态
     */
    int updateStatus(@Param("id") String id, @Param("status") String status);
}
