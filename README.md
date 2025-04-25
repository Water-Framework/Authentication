# Authentication Module
This modules needs a keystore defined or you can use the default one.

## Required properties

water.keystore.password=...
water.keystore.alias=...
water.keystore.file=...
water.private.key.password=...
water.rest.security.jwt.duration.millis=3600000
water.authentication.service.issuer=it.water.core.api.model.User

## Required modules

If using it.water.core.api.model.User as default service.issuer you can import

Spring:
    it.water.user:User-service-spring
Others:
    it.water.user:User-service