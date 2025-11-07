package store.bookscamp.auth.controller.request;

import jakarta.validation.constraints.NotBlank;

public record AdminLoginRequest (
    @NotBlank
    String username,
    @NotBlank
    String password
){
}
