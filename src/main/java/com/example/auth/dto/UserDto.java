package com.example.auth.dto;

import com.example.auth.model.Role;

import java.util.List;

public record UserDto(
        Long id,
        String username,
        String email,
        List<Role> roles
) {}