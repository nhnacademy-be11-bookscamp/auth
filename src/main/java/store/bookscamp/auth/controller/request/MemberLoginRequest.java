package store.bookscamp.auth.controller.request;

import jakarta.validation.constraints.NotBlank;

public record MemberLoginRequest (
        @NotBlank
        String username,
        @NotBlank
        String password
){
        public static MemberLoginDto toDto(MemberLoginRequest request){
        return new MemberLoginDto(request.username(), request.password());
    }
}

