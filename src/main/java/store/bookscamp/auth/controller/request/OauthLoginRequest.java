package store.bookscamp.auth.controller.request;

import jakarta.validation.constraints.NotBlank;

public record OauthLoginRequest (
        @NotBlank
        String username
){
}
