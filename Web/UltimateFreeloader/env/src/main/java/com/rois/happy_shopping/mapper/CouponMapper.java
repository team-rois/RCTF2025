package com.rois.happy_shopping.mapper;

import com.rois.happy_shopping.entity.Coupon;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/**
 * 创建CouponMapper接口，定义优惠券相关的数据库操作方法
 */
@Mapper
public interface CouponMapper {
    /**
     * 插入优惠券
     */
    int insert(Coupon coupon);
    
    /**
     * 根据ID查找优惠券
     */
    Coupon findById(@Param("id") String id);
    
    /**
     * 查找用户的可用优惠券
     */
    List<Coupon> findAvailableByUserId(@Param("userId") String userId);
    
    /**
     * 更新优惠券使用状态
     */
    int updateUsedStatus(@Param("id") String id, @Param("isUsed") Boolean isUsed);
    
    /**
     * 查找用户的所有优惠券
     */
    List<Coupon> findByUserId(@Param("userId") String userId);
}
