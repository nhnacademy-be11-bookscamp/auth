package store.bookscamp.auth.controller.request;

import jakarta.validation.constraints.NotBlank;
import store.bookscamp.auth.service.dto.MemberLoginDto;

public record MemberLoginRequest (
        @NotBlank
        String username,
        @NotBlank
        String password
){
    public MemberLoginDto toDto(MemberLoginRequest memberLoginRequest){
        return new MemberLoginDto(
                memberLoginRequest.username(),
                memberLoginRequest.password()
        );
    }
}
