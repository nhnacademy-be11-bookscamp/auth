package store.bookscamp.auth.controller.request;

import jakarta.validation.constraints.NotBlank;
import store.bookscamp.auth.service.dto.MemberLoginDto;

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

