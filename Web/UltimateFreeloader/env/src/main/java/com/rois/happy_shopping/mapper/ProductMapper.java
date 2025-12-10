package com.rois.happy_shopping.mapper;

import com.rois.happy_shopping.entity.Product;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/**
 * 创建ProductMapper接口，定义商品相关的数据库操作方法
 */
@Mapper
public interface ProductMapper {
    /**
     * 插入商品
     */
    int insert(Product product);
    
    /**
     * 根据ID查找商品
     */
    Product findById(@Param("id") String id);
    
    /**
     * 查找所有商品
     */
    List<Product> findAll();
}
