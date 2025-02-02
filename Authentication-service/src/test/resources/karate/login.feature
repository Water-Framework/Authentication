  # Generated with Water Generator
    # The Goal of feature test is to ensure the correct format of json responses
    # If you want to perform functional test please refer to ApiTest

  Feature: Login test

    Scenario: User gives right credentials and logs in succesfully

      Given header Content-Type = 'application/x-www-form-urlencoded'
      And header Accept = 'application/json'
      Given url serviceBaseUrl+'/water/authentication/login'
      # ---- Add entity fields here -----
      And request 'username=admin&password=admin'
      When method POST
      Then status 200
      # ---- Matching required response json ----
      And match response ==
        """
        { "token": #string }
        """

    Scenario: User gives wrong credentials and gets 401

      Given header Content-Type = 'application/x-www-form-urlencoded'
      And header Accept = 'application/json'
      Given url serviceBaseUrl+'/water/authentication/login'
      # ---- Add entity fields here -----
      And request 'username=admin&password=wrong'
      When method POST
      Then status 401

