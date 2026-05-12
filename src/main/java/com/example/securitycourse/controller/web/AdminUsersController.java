package com.example.securitycourse.controller.web;

import com.example.securitycourse.domain.AppUser;
import com.example.securitycourse.domain.Role;
import com.example.securitycourse.dto.UserCreateRequest;
import com.example.securitycourse.dto.UserUpdateRequest;
import com.example.securitycourse.repository.RoleRepository;
import com.example.securitycourse.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/admin/users")
@PreAuthorize("hasRole('ADMIN')")
public class AdminUsersController {

    private final UserService userService;
    private final RoleRepository roleRepository;

    public AdminUsersController(UserService userService, RoleRepository roleRepository) {
        this.userService = userService;
        this.roleRepository = roleRepository;
    }

    @GetMapping
    public String list(@RequestParam(defaultValue = "0") int page,
                       @RequestParam(defaultValue = "20") int size,
                       Model model) {
        Page<com.example.securitycourse.dto.UserResponse> users = userService.list(page, size);
        model.addAttribute("users", users);
        return "admin/users";
    }

    @GetMapping("/new")
    public String createForm(Model model) {
        model.addAttribute("form", new UserCreateRequest());
        model.addAttribute("allRoles", roleRepository.findAll().stream().map(Role::getName).sorted().toList());
        model.addAttribute("mode", "create");
        return "admin/user-form";
    }

    @PostMapping("/new")
    public String create(@Valid @ModelAttribute("form") UserCreateRequest form,
                         BindingResult bindingResult,
                         Model model,
                         HttpServletRequest http) {
        if (bindingResult.hasErrors()) {
            model.addAttribute("allRoles", roleRepository.findAll().stream().map(Role::getName).sorted().toList());
            model.addAttribute("mode", "create");
            return "admin/user-form";
        }
        try {
            userService.create(form, http);
            return "redirect:/admin/users?created";
        } catch (IllegalArgumentException ex) {
            bindingResult.reject("error", ex.getMessage());
            model.addAttribute("allRoles", roleRepository.findAll().stream().map(Role::getName).sorted().toList());
            model.addAttribute("mode", "create");
            return "admin/user-form";
        }
    }

    @GetMapping("/{id}/edit")
    public String editForm(@PathVariable UUID id, Model model) {
        AppUser user = userService.getById(id);
        UserUpdateRequest form = new UserUpdateRequest();
        form.setUsername(user.getUsername());
        form.setEmail(user.getEmail());
        form.setEnabled(user.isEnabled());
        form.setRoles(user.getRoles().stream().map(Role::getName).collect(Collectors.toSet()));

        model.addAttribute("userId", id);
        model.addAttribute("form", form);
        model.addAttribute("allRoles", roleRepository.findAll().stream().map(Role::getName).sorted().toList());
        model.addAttribute("mode", "edit");
        return "admin/user-form";
    }

    @PostMapping("/{id}/edit")
    public String edit(@PathVariable UUID id,
                       @Valid @ModelAttribute("form") UserUpdateRequest form,
                       BindingResult bindingResult,
                       Model model,
                       HttpServletRequest http) {
        if (bindingResult.hasErrors()) {
            model.addAttribute("userId", id);
            model.addAttribute("allRoles", roleRepository.findAll().stream().map(Role::getName).sorted().toList());
            model.addAttribute("mode", "edit");
            return "admin/user-form";
        }
        try {
            userService.update(id, form, http);
            return "redirect:/admin/users?updated";
        } catch (IllegalArgumentException ex) {
            bindingResult.reject("error", ex.getMessage());
            model.addAttribute("userId", id);
            model.addAttribute("allRoles", roleRepository.findAll().stream().map(Role::getName).sorted().toList());
            model.addAttribute("mode", "edit");
            return "admin/user-form";
        }
    }

    @PostMapping("/{id}/delete")
    public String delete(@PathVariable UUID id, HttpServletRequest http) {
        userService.delete(id, http);
        return "redirect:/admin/users?deleted";
    }

    @PostMapping("/{id}/lock")
    public String lock(@PathVariable UUID id, HttpServletRequest http) {
        userService.lock(id, http);
        return "redirect:/admin/users?locked";
    }

    @PostMapping("/{id}/unlock")
    public String unlock(@PathVariable UUID id, HttpServletRequest http) {
        userService.unlock(id, http);
        return "redirect:/admin/users?unlocked";
    }
}
