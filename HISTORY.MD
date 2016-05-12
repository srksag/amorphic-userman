## 1.0.0
- Fixed typo that prevented password change messages from coming out
## 0.1.30
- Added segragation by channel (filterProperty/filterValue) per application
## 0.1.28
- lower case login
## 0.1.27
- Support for knex
## 0.1.25
- Fixed information leak issue
## 0.1.24
- Changes for admin users
## 0.1.23
- Typeo in password composition 
## 0.1.22
- Allow login to provide new password and change password
## 0.1.21
- Make sure email validation code has leading zeros rather than suppressing them
## 0.1.20
- Support for deferred email changes
## 0.1.19
For admin users
- Password lockout on bad attempts
- Password expiration
- Forbid use of the last n passwords
- Forcing password changes on new accounts
- reset of admin user passwords
- Composition rules that are principal specific
## 0.1.18
* Fixed lost password
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
