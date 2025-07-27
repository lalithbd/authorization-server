package com.mcueen.auth.service;

import com.mcueen.auth.controller.dto.UserCreateDto;
import com.mcueen.auth.exception.AuthServiceException;
import org.modelmapper.MappingException;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;

import java.lang.reflect.Type;

public interface CommonService {

    Logger logger = LoggerFactory.getLogger(CommonService.class);
    ModelMapper modelMapper = new ModelMapper();

    default <D> D map(UserCreateDto userCreateDto, Type destination) throws AuthServiceException {
        if (userCreateDto == null) {
            return null;
        }
        try {
            return modelMapper.map(userCreateDto, destination);
        } catch (MappingException e) {
            logger.error("Mapping error occurred : {}", e.getMessage());
            throw new AuthServiceException(HttpStatus.INTERNAL_SERVER_ERROR, "Mapping error");
        }
    }
}
