package com.aegis.api;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class SampleController {

    @GetMapping("/ping")
    public Map<String, Object> ping(HttpServletRequest req) {
        return Map.of(
                "ok", true,
                "subject", req.getAttribute("aegis.subject"),
                "algorithm", req.getAttribute("aegis.algorithm")
        );
    }
}
