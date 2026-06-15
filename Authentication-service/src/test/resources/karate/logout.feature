# Generated with Water Generator
# M13 — Logout / token revocation REST test
# Exercises POST /water/authentication/logout
#
# serviceBaseUrl is provided by karate-config.js (built from protocol/host/webServerPort properties).
# The endpoint is @LoggedIn — it reads the Authorization header.
# Successful logout returns HTTP 200 { "result": "ok" }.
# A request without a valid token returns HTTP 401.

Feature: Authentication Logout

  Scenario: Login then logout — token is accepted and response is ok

    # Step 1: obtain a valid JWT via login
    Given header Content-Type = 'application/x-www-form-urlencoded'
    And header Accept = 'application/json'
    Given url serviceBaseUrl+'/water/authentication/login'
    And request 'username=admin&password=admin'
    When method POST
    Then status 200
    And match response.token == '#string'
    * def bearerToken = response.token

    # Step 2: call logout with the Bearer token
    Given url serviceBaseUrl+'/water/authentication/logout'
    And header Authorization = 'Bearer ' + bearerToken
    And header Accept = 'application/json'
    When method POST
    Then status 200
    And match response == { result: 'ok' }

  Scenario: Logout without Authorization header returns 401

    Given url serviceBaseUrl+'/water/authentication/logout'
    And header Accept = 'application/json'
    When method POST
    Then status 401
