
package it.water.authentication.service;

import com.intuit.karate.junit5.Karate;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest(classes = AuthenticationApplication.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "water.testMode=true",
        // User module generates a random admin password when unset (security hardening);
        // pin it so the admin/admin logins in the shared Karate features succeed.
        "water.user.admin.default.password=admin"
})
public class AuthenticationRestSpringApiTest {
    @LocalServerPort
    private int serverPort;

    @Karate.Test
    Karate restInterfaceTest() {
        return Karate.run("../Authentication-service/src/test/resources/karate")
                .systemProperty("webServerPort", String.valueOf(serverPort))
                .systemProperty("host", "localhost")
                .systemProperty("protocol", "http");
    }
}
