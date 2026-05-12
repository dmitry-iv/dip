package com.example.securitycourse.controller.api;

import com.example.securitycourse.domain.AppUser;
import com.example.securitycourse.dto.TwoFactorSetupResponse;
import com.example.securitycourse.repository.UserRepository;
import com.example.securitycourse.security.AuthPrincipal;
import com.example.securitycourse.service.TwoFactorService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/2fa")
public class TwoFactorApiController {

    private final TwoFactorService twoFactorService;
    private final UserRepository userRepository;

    public TwoFactorApiController(TwoFactorService twoFactorService, UserRepository userRepository) {
        this.twoFactorService = twoFactorService;
        this.userRepository = userRepository;
    }

    @PostMapping("/setup")
    public TwoFactorSetupResponse setup(@AuthenticationPrincipal AuthPrincipal principal) {
        AppUser user = userRepository.findById(principal.getUserId())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        TwoFactorService.SetupChallenge ch = twoFactorService.initiateSetup(user);
        return new TwoFactorSetupResponse(ch.secret(), ch.qrCodeDataUri());
    }

    @PostMapping("/confirm")
    public ResponseEntity<Map<String, Object>> confirm(@AuthenticationPrincipal AuthPrincipal principal,
                                                       @RequestBody Map<String, String> body,
                                                       HttpServletRequest http) {
        String secret = body.get("secret");
        String code = body.get("code");
        List<String> backup = twoFactorService.confirmSetup(principal.getUserId(), secret, code, http);
        return ResponseEntity.ok(Map.of("backupCodes", backup));
    }

    @PostMapping("/disable")
    public ResponseEntity<Void> disable(@AuthenticationPrincipal AuthPrincipal principal, HttpServletRequest http) {
        twoFactorService.disable(principal.getUserId(), http);
        return ResponseEntity.noContent().build();
    }
}