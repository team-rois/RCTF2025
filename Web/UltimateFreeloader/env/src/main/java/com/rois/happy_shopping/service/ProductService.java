package com.rois.happy_shopping.service;

import com.rois.happy_shopping.entity.Product;
import com.rois.happy_shopping.mapper.ProductMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 创建ProductService服务类，处理商品相关的业务逻辑
 */
@Service
public class ProductService {

    @Autowired
    private ProductMapper productMapper;

    /**
     * 获取所有商品
     */
    public List<Product> getAllProducts() {
        return productMapper.findAll();
    }

    /**
     * 根据ID获取商品
     */
    public Product getProductById(String id) {
        return productMapper.findById(id);
    }
}
