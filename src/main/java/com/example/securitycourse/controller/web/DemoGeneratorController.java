package com.example.securitycourse.controller.web;

import com.example.securitycourse.service.DemoDataService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping("/admin/demo-generator")
@PreAuthorize("hasRole('ADMIN')")
public class DemoGeneratorController {

    private static final Logger log = LoggerFactory.getLogger(DemoGeneratorController.class);

    private final DemoDataService demoDataService;

    public DemoGeneratorController(DemoDataService demoDataService) {
        this.demoDataService = demoDataService;
    }

    @GetMapping
    public String page(Model model) {
        return "admin/demo-generator";
    }

    @PostMapping("/generate")
    public String generate(RedirectAttributes ra) {
        try {
            DemoDataService.GenerationReport report = demoDataService.generate();
            ra.addFlashAttribute("savedOk", String.format(
                    "Сгенерировано: %d событий аудита и %d инцидентов",
                    report.auditEventsCreated(), report.incidentsCreated()));
        } catch (Exception e) {
            log.error("Demo generation failed", e);
            ra.addFlashAttribute("errorMsg", "Ошибка генерации: " + e.getMessage());
        }
        return "redirect:/admin/demo-generator";
    }

    @PostMapping("/cleanup")
    public String cleanup(RedirectAttributes ra) {
        try {
            DemoDataService.CleanupReport report = demoDataService.cleanup();
            ra.addFlashAttribute("savedOk", String.format(
                    "Удалено: %d событий аудита и %d инцидентов. " +
                            "ВНИМАНИЕ: hash-цепочка журнала аудита теперь нарушена — это нормально " +
                            "(удаление детектируется системой). Для сброса очистите audit_log целиком " +
                            "и last_hash в audit_chain_state через pgAdmin.",
                    report.auditEventsRemoved(), report.incidentsRemoved()));
        } catch (Exception e) {
            log.error("Demo cleanup failed", e);
            ra.addFlashAttribute("errorMsg", "Ошибка очистки: " + e.getMessage());
        }
        return "redirect:/admin/demo-generator";
    }
}