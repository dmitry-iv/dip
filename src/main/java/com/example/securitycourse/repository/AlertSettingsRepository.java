package com.example.securitycourse.repository;

import com.example.securitycourse.domain.AlertSettings;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AlertSettingsRepository extends JpaRepository<AlertSettings, Short> {
}