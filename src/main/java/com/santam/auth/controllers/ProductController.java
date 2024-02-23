package com.santam.auth.controllers;

import com.santam.auth.domain.product.Product;
import com.santam.auth.domain.product.ProductRequestDTO;
import com.santam.auth.domain.product.ProductResponseDTO;
import com.santam.auth.repositories.ProductRepository;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController()
@RequestMapping("product")
public class ProductController {
    @Autowired
    private ProductRepository repository;

    @PostMapping
    public ResponseEntity<Void> postProduct(@RequestBody @Valid ProductRequestDTO body) {
        Product product = new Product(body);
        repository.save(product);
        return ResponseEntity.ok().build();
    }

    @GetMapping
    public ResponseEntity<List<ProductResponseDTO>> getAll() {
        List<ProductResponseDTO> products = repository.findAll().stream().map(ProductResponseDTO::new).toList();
        return ResponseEntity.ok().body(products);
    }
}
