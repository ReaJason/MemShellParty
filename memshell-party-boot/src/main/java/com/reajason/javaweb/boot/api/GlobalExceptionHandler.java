package com.reajason.javaweb.boot.api;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.InvalidInputException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;

/**
 * @author ReaJason
 * @since 2024/5/30
 */
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ResponseStatus(HttpStatus.NOT_FOUND)
    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<?> handleNoResourceException() {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
    }

    /**
     * 入参不合法（缺字段、未知 server/tool/packer、非法 class 字节等）不是服务端故障，统一返回 400。
     */
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(InvalidInputException.class)
    public ErrorResponse handleInvalidInputException(InvalidInputException exception) {
        return new ErrorResponse(exception.getMessage());
    }

    /**
     * 解码与注册表层的通用参数错误：Base64 非法、class 文件头不符、打包方式不存在等。
     */
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(IllegalArgumentException.class)
    public ErrorResponse handleIllegalArgumentException(IllegalArgumentException exception) {
        return new ErrorResponse(exception.getMessage());
    }

    /**
     * 请求体不是合法 JSON 或字段类型不匹配。
     */
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ErrorResponse handleUnreadableBody(HttpMessageNotReadableException exception) {
        return new ErrorResponse("Malformed request body: " + exception.getMostSpecificCause().getMessage());
    }

    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ExceptionHandler(GenerationException.class)
    public ErrorResponse handleGenerationException(GenerationException exception) {
        return new ErrorResponse(exception.getMessage());
    }

    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ExceptionHandler(Throwable.class)
    public ErrorResponse handleThrowable(Throwable throwable) {
        log.error("Internal Exception", throwable);
        return new ErrorResponse(throwable.getMessage());
    }
}
