package com.example.securitycourse.controller.api;

import com.example.securitycourse.dto.UserCreateRequest;
import com.example.securitycourse.dto.UserResponse;
import com.example.securitycourse.dto.UserUpdateRequest;
import com.example.securitycourse.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/admin/users")
public class AdminUserApiController {

    private final UserService userService;

    public AdminUserApiController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping
    public Page<UserResponse> list(@RequestParam(defaultValue = "0") int page,
                                  @RequestParam(defaultValue = "20") int size) {
        return userService.list(page, size);
    }

    @PostMapping
    public ResponseEntity<UserResponse> create(@Valid @RequestBody UserCreateRequest req, HttpServletRequest http) {
        UserResponse created = userService.create(req, http);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @PutMapping("/{id}")
    public UserResponse update(@PathVariable UUID id, @Valid @RequestBody UserUpdateRequest req, HttpServletRequest http) {
        return userService.update(id, req, http);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable UUID id, HttpServletRequest http) {
        userService.delete(id, http);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{id}/lock")
    public ResponseEntity<Void> lock(@PathVariable UUID id, HttpServletRequest http) {
        userService.lock(id, http);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{id}/unlock")
    public ResponseEntity<Void> unlock(@PathVariable UUID id, HttpServletRequest http) {
        userService.unlock(id, http);
        return ResponseEntity.noContent().build();
    }
}
