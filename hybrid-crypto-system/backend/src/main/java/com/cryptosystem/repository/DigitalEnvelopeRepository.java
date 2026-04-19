package com.cryptosystem.repository;

import com.cryptosystem.model.DigitalEnvelope;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface DigitalEnvelopeRepository extends JpaRepository<DigitalEnvelope, Long> {
    List<DigitalEnvelope> findAllByShreddedFalseOrderByUploadedAtDesc();
    List<DigitalEnvelope> findAllByOrderByUploadedAtDesc();
}
