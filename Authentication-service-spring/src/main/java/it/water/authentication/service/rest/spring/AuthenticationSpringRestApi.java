/*
 * Copyright 2024 Aristide Cittadino
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package it.water.authentication.service.rest.spring;

import com.fasterxml.jackson.annotation.JsonView;
import it.water.authentication.api.rest.AuthenticationRestApi;
import it.water.core.api.service.rest.FrameworkRestApi;
import it.water.core.api.service.rest.WaterJsonView;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Map;

/**
 * @Author Aristide Cittadino
 * Interface exposing same methods of its parent AuthenticationRestApi but adding Spring annotations.
 * Swagger annotation should be found because they have been defined in the parent AuthenticationRestApi.
 */
@RequestMapping("/authentication")
@FrameworkRestApi
public interface AuthenticationSpringRestApi extends AuthenticationRestApi {
    @PostMapping(path = "/login", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @JsonView(WaterJsonView.Public.class)
    @Override
    Map<String, String> login(@RequestParam("username") String username,@RequestParam("password") String password);
}
