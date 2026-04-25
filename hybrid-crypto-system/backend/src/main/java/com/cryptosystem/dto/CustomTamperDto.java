package com.cryptosystem.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class CustomTamperDto {

    @NotBlank(message = "Tampered ciphertext is required")
    private String encryptedFileBase64;

    private String ivBase64;
    private String note;
}
