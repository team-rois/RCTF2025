package com.rois.happy_shopping.controller;

import com.rois.happy_shopping.common.Result;
import com.rois.happy_shopping.entity.Product;
import com.rois.happy_shopping.service.ProductService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * ProductController handles HTTP requests related to products
 */
@RestController
@RequestMapping("/api/product")
@CrossOrigin(origins = "*")
public class ProductController {

    @Autowired
    private ProductService productService;

    /**
     * Get all products
     */
    @GetMapping("/list")
    public Result<List<Product>> getAllProducts() {
        List<Product> products = productService.getAllProducts();
        return Result.success("Get product list successfully", products);
    }


    @GetMapping("/{id}")
    public Result<Product> getProductById(@PathVariable String id) {
        Product product = productService.getProductById(id);
        if (product != null) {
            return Result.success("Get product details successfully", product);
        } else {
            return Result.error("Product not found");
        }
    }
}
