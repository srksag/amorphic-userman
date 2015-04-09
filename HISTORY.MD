## 0.1.17
* Don't auto-login on email verification
* Don't destroy email change token on verification
## 0.1.16
* Made case insensitive login work with special characters
## 0.1.15
* Case insensitive login
## 0.1.14
* New config element validateEmailForce to force email validation prior to login
## 0.1.13
* Change email was not handling emails correctly
## 0.1.12
* Allow user friendly validation codes to go in emails
* Added verify from token when principal already fetched
## 0.1.11
* Admin creation in one step
## 0.1.10
* Don't use configurable principal in securityContext
## 0.1.09
* Let you configure principal property in controller
## 0.1.07
* Compatibility with requirement that all object.create must have a classname
## 0.1.06
* No longer require that Principal has an init method
## 0.1.05
* Can use xxxField ids in form container to limit scope of validation
## 0.1.04
* Allowed principal declaration to be an array
## 0.1.03
* Registration ensuring password verification was not working properly
* Registration itself on verify email was not setting things up properly
* When creating the default user there was no first and last name attached
