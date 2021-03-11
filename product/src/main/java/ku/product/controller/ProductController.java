package ku.product.controller;

import ku.product.model.Product;
import ku.product.service.ProductService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/products")
public class ProductController
{
	@Autowired
	ProductService productService;

	@GetMapping
	public List<Product> getAll()
	{
		return productService.getAllProducts();
	}

	@PostMapping
	public ResponseEntity<String> createProduct(@RequestBody Product product)
	{
		productService.createProduct(product);
		return new ResponseEntity<String>("Product created successfully",	HttpStatus.OK);
	}
}
