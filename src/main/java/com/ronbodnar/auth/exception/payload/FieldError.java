package com.ronbodnar.auth.exception.payload;

import com.ronbodnar.auth.exception.ErrorCode;

import com.fasterxml.jackson.annotation.JsonIgnore;

public record FieldError(
        ErrorCode errorCode,
        String field,
        @JsonIgnore String logMessage
) {

    public FieldError(ErrorCode errorCode) {
        this(errorCode, null, null);
    }

    public FieldError(ErrorCode errorCode, String logMessage) {
        this(errorCode, null, logMessage);
    }

}