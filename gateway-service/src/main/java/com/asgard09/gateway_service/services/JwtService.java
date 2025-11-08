package com.asgard09.gateway_service.services;

import io.jsonwebtoken.Claims;

public interface JwtService {
    Claims getAllClaimsFromToken(String token);
    boolean isTokenExpired(String token);
    boolean isInValid(String token);

}
