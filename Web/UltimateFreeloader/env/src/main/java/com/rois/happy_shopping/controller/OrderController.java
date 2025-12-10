package com.rois.happy_shopping.controller;

import com.rois.happy_shopping.common.Result;
import com.rois.happy_shopping.dto.OrderRequestDTO;
import com.rois.happy_shopping.entity.Order;
import com.rois.happy_shopping.service.OrderService;
import com.rois.happy_shopping.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/order")
@CrossOrigin(origins = "*")
public class OrderController {

    @Autowired
    private OrderService orderService;

    @Autowired
    private JwtUtil jwtUtil;

    /**
     * Create order
     */
    @PostMapping("/create")
    public Result<?> createOrder(@Valid @RequestBody OrderRequestDTO orderRequest, HttpServletRequest request) {
        String token = getTokenFromRequest(request);
        if (token == null || !jwtUtil.validateToken(token)) {
            return Result.error(401, "Unauthorized access");
        }

        String userId = jwtUtil.getUserIdFromToken(token);
        Map<String, Object> result = orderService.createOrder(userId, orderRequest);
        if ((Boolean) result.get("success")) {
            return Result.success("Order created successfully", result);
        } else {
            return Result.error((String) result.get("message"));
        }
    }

    /**
     * Get user order list
     */
    @GetMapping("/my")
    public Result<List<Order>> getMyOrders(HttpServletRequest request) {
        String token = getTokenFromRequest(request);
        if (token == null || !jwtUtil.validateToken(token)) {
            return Result.error(401, "Unauthorized access");
        }

        String userId = jwtUtil.getUserIdFromToken(token);
        List<Order> orders = orderService.getUserOrders(userId);
        return Result.success("Get order list successfully", orders);
    }

    /**
     * Get order details by ID
     */
    @GetMapping("/{id}")
    public Result<Order> getOrderById(@PathVariable String id, HttpServletRequest request) {
        String token = getTokenFromRequest(request);
        if (token == null || !jwtUtil.validateToken(token)) {
            return Result.error(401, "Unauthorized access");
        }

        Order order = orderService.getOrderById(id);
        if (order != null) {
            // Verify order belongs to current user
            String userId = jwtUtil.getUserIdFromToken(token);
            if (!order.getUserId().equals(userId)) {
                return Result.error(403, "No permission to access this order");
            }
            return Result.success("Get order details successfully", order);
        } else {
            return Result.error("Order not found");
        }
    }

    /**
     * Order refund
     */
    @PostMapping("/refund/{id}")
    public Result<?> refundOrder(@PathVariable String id, HttpServletRequest request) {
        String token = getTokenFromRequest(request);
        if (token == null || !jwtUtil.validateToken(token)) {
            return Result.error(401, "Unauthorized access");
        }

        String userId = jwtUtil.getUserIdFromToken(token);
        Map<String, Object> result = orderService.refundOrder(id, userId);
        
        if ((Boolean) result.get("success")) {
            return Result.success("Refund successful", result);
        } else {
            return Result.error((String) result.get("message"));
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
