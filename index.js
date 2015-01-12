module.exports.userman_mixins = function (objectTemplate, requires, moduleConfig, nconf)
{

    if (typeof(require) != "undefined") {
        var Q = require('q');
        var crypto = require('crypto');
        var urlparser = require('url');
    }

    function log(level, message) {
        objectTemplate.log(level, message);
    }

    /*
     * SecurityContext can be retrieved using getSecurityContext on any object to
     * find out who is logged in and what there roll is
     */
    objectTemplate.globalInject(function (obj) {
        obj.getSecurityContext = function () {
            return objectTemplate.controller.securityContext || new SecurityContext();
        }
    });

    var Controller = requires[moduleConfig.controller.require][moduleConfig.controller.template]
    var principals = moduleConfig.principal instanceof Array ? moduleConfig.principal : [moduleConfig.principal];
    var controllerFields = moduleConfig.controller.fields || {};
    var principalProperty = controllerFields.principal || 'principal';

    for (var ix = 0; ix < principals.length; ++ix)
    {
        var Principal = requires[principals[ix].require][principals[ix].template];

        Principal.mixin(
            {
                // These secure elements are NEVER transmitted

                passwordHash: {toClient: false, toServer: false, type: String},
                passwordSalt: {toClient: false, toServer: false, type: String },

                passwordChangeHash: {toClient: false, toServer: false, type: String, value: ""},
                passwordChangeSalt: {toClient: false, toServer: false, type: String, value: ""},
                passwordChangeExpires: {toClient: false, toServer: false, type: Date},

                validateEmailCode: {toClient: false, toServer: false, type: String}, // If present status is pending
                emailValidated:    {toServer: false, type: Boolean, value: false},


                role: {toServer: false, type: String, init: "user", values: {
                    "user": "User",             // A normal user
                    "admin": "Administrator"}   // An administrative user
                },
                roleSet: {on: "server", body: function (role) {
                    if (this.getSecurityContext.role == 'admin' && (role == 'admin' || role == 'user'))
                        this.role = role;
                    else
                        throw {code: "role_change", text: "You cannot change roles"};
                }},
                isAdmin: function () {
                    return this.role == 'admin';
                },
                /**
                 * Create a password hash and save the object
                 *
                 * @param password
                 * @returns {*} promise (true) when done
                 * throws an exception if the password does not meet password rules
                 */
                establishPassword: function (password, noValidate) {
                    if (!noValidate)
                        this.validateNewPassword(password);

                    // Get a random number as the salt
                    return this.getSalt().then(function (salt) {
                        this.passwordSalt = salt;
                        this.passwordChangeHash = "";

                        // Create a hash of the password with the salt
                        return this.getHash(password, salt);

                    }.bind(this)).then(function (hash) {
                        // Save this for verification later
                        this.passwordHash = hash;
                        return this.persistSave().then(function (id) {
                            return Q(true);
                        }.bind(this));

                    }.bind(this));
                },

                /**
                 * Check password rules for a new password
                 *
                 * @param password
                 * @return {*}
                 */
                validateNewPassword: function (password) {
                    if (password.length < 6 || password.length > 30 || !password.match(/[A-Za-z]/) || !password.match(/[0-9]/))

                        throw {code: "password_composition",
                            text: "Password must be 6-30 characters with at least one letter and one number"};
                },

                /**
                 * Return a password hash
                 *
                 * @param password
                 * @param salt
                 * @return {*}
                 */
                getHash: function (password, salt) {
                    return Q.ninvoke(crypto, 'pbkdf2', password, salt, 10000, 64).then(function (whyAString) {
                        return Q((new Buffer(whyAString, 'binary')).toString('hex'));
                    });
                },

                /**
                 * Get a secure random string for the salt
                 *
                 * @return {*}
                 */
                getSalt: function () {
                    return Q.ninvoke(crypto, 'randomBytes', 64).then(function (buf) {
                        return Q(buf.toString('hex'));
                    });
                },

                /*
                 * Make registration pending verification of a code usually sent by email
                 */
                setEmailVerificationCode: function () {
                    this.emailValidated = false;
                    if (moduleConfig.validateEmailHumanReadable) {
                        this.validateEmailCode = Math.floor(Math.random() * 10000);
                        return this.persistSave();
                    } else
                        return this.getSalt().then(function (salt) {
                            this.validateEmailCode = salt.substr(10, 6);
                            return this.persistSave();

                        }.bind(this));
                },

                /*
                 * Verify the email code passed in and reset the principal record to allow registration to proceed
                 */
                consumeEmailVerificationCode: function (code) {
                    if (code != this.validateEmailCode)
                        throw {code: "inavlid_validation_link", text: "Incorrect email validation link"}

                    this.validateEmailCode = false;
                    this.emailValidated = true;
                    return this.persistSave();
                },

                /**
                 * Create a one-way hash for changing passwords
                 * @returns {*}
                 */
                setPasswordChangeHash: function () {
                    var token;
                    return this.getSalt().then(function (salt) {
                        token = salt;
                        return this.getSalt();
                    }.bind(this)).then(function (salt) {
                        this.passwordChangeSalt = salt;
                        return this.getHash(token, salt);
                    }.bind(this)).then(function (hash) {
                        this.passwordChangeHash = hash;
                        this.passwordChangeExpires = new Date(((new Date()).getTime() +
                            (moduleConfig.passwordChangeExpiresHours || 24) * 60 * 60 * 1000));
                        return this.persistSave();
                    }.bind(this)).then(function () {
                        return Q(token);
                    }.bind(this));
                },

                /**
                 * Consume a password change token and change the password
                 *
                 * @param token
                 * @returns {*}
                 */
                consumePasswordChangeToken: function (token, newPassword) {
                    if (!this.passwordChangeHash)
                        throw {code: "password_reset_used", text: "Password change link already used"};
                    return this.getHash(token, this.passwordChangeSalt).then(function (hash) {
                        if (this.passwordChangeHash != hash)
                            throw {code: "invalid_password_change_link", text: "Incorrect password change link"};
                        if (this.passwordChangeExpires.getTime() < (new Date()).getTime())
                            throw {code: "password_change_link_expired", text: "Password change link expired"};
                        return this.establishPassword(newPassword);
                    }.bind(this));
                },

                /**
                 * Verify a password on login (don't reveal password vs. user name is bad)
                 *
                 * @param password
                 * @returns {*}
                 */
                authenticate: function (password, loggedIn, novalidate) {
                    if (!novalidate && this.validateEmailCode && moduleConfig.validateEmailForce)

                        throw {code: "registration_unverified",
                            text: "Please click on the link in your verification email to activate this account"};

                    return this.getHash(password, this.passwordSalt).then(function (hash) {
                        if (this.passwordHash !== hash)
                            throw loggedIn ?
                            {code: "invalid_password", text: "Incorrect password"} :
                            {code: "invalid_email_or_password", text: "Incorrect email or password"};

                        return Q(true);

                    }.bind(this))
                }
            });
    }

    var Principal = requires[principals[0].require][principals[0].template];
    var SecurityContext = objectTemplate.create("SecurityContext",
        {
            principal: {toServer: false, type: Principal},
            role: {toServer: false, type: String},
            init: function (principal, role) {
                this.principal = principal;
                this.role = role;
            },
            isLoggedIn: function () {
                return !!this.role;
            },
            isAdmin: function () {
                return this.isLoggedIn() && this.principal.role == 'admin';
            }
        });

    // Inject principal
    if (!Controller.getProperties()[principalProperty])
    {
        var principalDef = {};
        principalDef[principalProperty] = {toServer: false, type: Principal};
        Controller.mixin(principalDef);
    }
    Controller.mixin(
        {
            firstName:              {type: String, value: "", length: 50, rule: ["name", "required"]},
            lastName:               {type: String, value: "", length: 50, rule: ["name", "required"]},
            email:                  {type: String, value: "", length: 50, rule: ["text", "email", "required"]},
            newEmail:               {type: String, value: "", length: 50, rule: ["text", "email", "required"]},

            // Secure variables never leaked to the client

            password:               {toClient: false, type: String, value: ""},
            confirmPassword:        {toClient: false, type: String, value: "", rule:["required"]},
            newPassword:            {toClient: false, type: String, value: "", rule:["required"]},

            passwordChangeHash:     {toClient: false, type: String},
            verifyEmailCode:        {toClient: false, type: String},

            loggedIn:               {toServer: false, type: Boolean, value: false},
            loggedInRole:           {toServer: false, type: String},

            isAdmin: function () {
                return this.loggedIn && this.loggedInRole == "admin";
            },
            isLoggedIn: function () {
                return !!this.loggedIn;
            },
            securityContext:        {type: SecurityContext},

            createAdmin: function () {
                Principal.countFromPersistWithQuery({role: "admin"}).then(function (count) {
                    if (count == 0) {
                        var admin = new Principal();
                        admin.role = "admin";
                        admin.email = moduleConfig.defaultEmail || "amorphic@amorphic.com";
                        admin.firstName = "Admin";
                        admin.lastName = "User";
                        admin.role = moduleConfig.defaultRole || "admin";
                        return admin.establishPassword(moduleConfig.defaultPassword || "admin", true);
                    } else
                        return Q(false);
                });
            },

            /**
             * Create a new principal if one does not exist. This method is used by the currently logged in user to create
             * new users. The principal info comes from the an object which should have the following properties:
             *
             * firstName, lastName, email, newPassword, confirmPassword, role
             */
            createNewAdmin: {
                on: "server",
                validate: function(){
                    return this.validate(document.getElementById('publicRegisterFields'));
                },
                body: function(newAdmin, url, pageConfirmation, pageInstructions){

                    // Check for security context of security admin
                    if(this.loggedInRole !== moduleConfig.defaultRole){
                        throw {code: 'cannotcreateadmin', text: "Only a security admin can create users"};
                    }
                    if (newAdmin.newPassword != newAdmin.confirmPassword)
                        throw {code: 'passwordmismatch', text: "Password's are not the same"};

                    var principal;

                    url = urlparser.parse(url, true);
                    return Principal.countFromPersistWithQuery({email: newAdmin.email}).then( function (count)
                    {
                        if (count > 0)
                            throw {code: "email_registered", text:"This email is already registered"};

                        // this[principalProperty] = this[principalProperty] || new Principal();
                        principal = new Principal();
                        principal.email = newAdmin.email;
                        principal.firstName = newAdmin.firstName;
                        principal.lastName = newAdmin.lastName;
                        principal.role = newAdmin.role;
                        return principal.establishPassword(newAdmin.newPassword);

                    }.bind(this)).then( function() {
                        if (moduleConfig.validateEmail)
                            return principal.setEmailVerificationCode();
                        else {
                            return Q(false);
                        }
                    }.bind(this)).then (function ()
                    {
                        this.sendEmail(moduleConfig.validateEmail ? "register_verify": "register",
                            principal.email, this.firstName + " " + this.lastName, [
                                {name: "firstName", content: this.firstName},
                                {name: "email", content: this.email},
                                {name: "link", content: url.protocol + "//" + url.host.replace(/:.*/, '') +
                                    (url.port > 1000 ? ':' + url.port : '') +
                                    "?email=" + encodeURIComponent(this.email) +
                                    "&code=" + principal.validateEmailCode + "#verify_email"}
                            ]);
                        if (moduleConfig.validateEmail && pageInstructions)
                            return this.setPage(pageInstructions);
                        if (!moduleConfig.validateEmail && pageConfirmation)
                            return this.setPage(pageConfirmation);

                    }.bind(this))
                }},

            /**
             * Create a new principal if one does not exist and consider ourselves logged in
             *
             * @param password
             */
            publicRegister: {
                on: "server",
                validate: function () {
                    return this.validate(document.getElementById('publicRegisterFields'));
                },
                body: function (url, pageConfirmation, pageInstructions)
                {
                    if (this.newPassword != this.confirmPassword)
                        throw {code: 'passwordmismatch', text: "Password's are not the same"};

                    var principal;

                    url = urlparser.parse(url, true);
                    return Principal.countFromPersistWithQuery({email: this.email}).then( function (count)
                    {
                        if (count > 0)
                            throw {code: "email_registered", text:"This email already registered"};

                        this[principalProperty] = this[principalProperty] || new Principal();
                        principal = this[principalProperty];
                        principal.email = this.email;
                        principal.firstName = this.firstName;
                        principal.lastName = this.lastName;
                        return principal.establishPassword(this.newPassword);

                    }.bind(this)).then( function() {
                        if (moduleConfig.validateEmail)
                            return principal.setEmailVerificationCode();
                        else
                            return Q(true);
                    }.bind(this)).then( function () {
                        if (!moduleConfig.validateEmail || moduleConfig.validateEmailAndLogin)
                            this.setLoggedInState(principal);
                        this.sendEmail(moduleConfig.validateEmail ? "register_verify": "register",
                            principal.email, principal.firstName + " " + principal.lastName, [
                                {name: "firstName", content: this.firstName},
                                {name: "email", content: this.email},
                                {name: "link", content: url.protocol + "//" + url.host.replace(/:.*/, '') +
                                    (url.port > 1000 ? ':' + url.port : '') +
                                    "?email=" + encodeURIComponent(this.email) +
                                    "&code=" + principal.validateEmailCode + "#verify_email"},
                                {name: "verificationCode", content: this[principalProperty].validateEmailCode}

                            ]);
                        if (moduleConfig.validateEmail && pageInstructions)
                            return this.setPage(pageInstructions);
                        if (!moduleConfig.validateEmail && pageConfirmation)
                            return this.setPage(pageConfirmation);

                    }.bind(this))
                }},

            /**
             * login the user
             */
            publicLogin: {
                on: "server",
                validate: function () {return this.validate(document.getElementById('publicLoginFields'))},
                body: function(page)
                {
                    if (this.loggedIn)
                        throw {code: "already_loggedin", text: "Already logged in"};

                    return Principal.getFromPersistWithQuery({email: this.email}).then( function (principals)
                    {
                        if (principals.length == 0) {
                            log(1, "Log In attempt for " + this.email + " failed (invalid email)");
                            throw {code: "invalid_email_or_password",
                                text: "Incorrect email or password"};
                        }
                        var principal = principals[0];
                        return principal.authenticate(this.password).then( function()
                        {
                            this.setLoggedInState(principal);
                            return page ? this.setPage(page) : Q(true);

                        }.bind(this))

                    }.bind(this));
                }},

            /**
             *  Set up all fields to indicate logged in
             */
            setLoggedInState: function (principal)
            {
                this.loggedIn = true;
                this.loggedInRole = principal.role;
                this[principalProperty] = principal;

                // One way so you can't spoof from client
                this.securityContext = new SecurityContext(principal);
            },

            /**
             *  Set up all fields to indicate logged out
             */
            setLoggedOutState: function ()
            {
                this[principalProperty] = null;
                this.loggedIn = false;
                this.loggedInRole = null;
                this.securityContext = null;
            },

            /*
             * logout the current user
             */
            publicLogout: {on: "server", body: function(page)
            {
                log(1, "Customer " + this.email + " logged out");
                this.setLoggedOutState();
                return page ? this.setPage(page) : Q(true);
            }},

            /**
             * change an email address for a logged in user
             */
            changeEmail: {
                on: "server",
                validate: function () {
                    return this.validate(document.getElementById('changeEmailFields'))},
                body: function(page, url)
                {
                    url = urlparser.parse(url, true);
                    var principal = this[principalProperty];
                    var oldEmail = principal.email;
                    var newEmail = this.newEmail;

                    return Q(true).then(function () {
                        return principal.authenticate(this.password, null, true);
                    }.bind(this)).then (function () {
                        return Principal.countFromPersistWithQuery({email: newEmail})
                    }.bind(this)).then(function (count) {
                        if (count > 0)
                            throw {code: "email_registered", text:"This email already registered"};
                    }.bind(this)).then( function() {
                        if (moduleConfig.validateEmail)
                            return principal.setEmailVerificationCode();
                        else {
                            return Q(false);
                        }
                    }.bind(this)).then( function() {
                        this.email = newEmail;


                        principal.email = newEmail;
                        principal.persistSave();

                        this.sendEmail("email_changed", oldEmail, principal.email,
                                principal.firstName + " " + principal.lastName, [
                                {name: "oldEmail", content: oldEmail},
                                {name: "email", content: newEmail},
                                {name: "firstName", content: principal.firstName}
                            ]);

                        this.sendEmail(moduleConfig.validateEmail ? "email_changed_verify" : "email_changed",
                            newEmail,  principal.firstName + " " + principal.lastName, [
                                {name: "oldEmail", content: oldEmail},
                                {name: "email", content: newEmail},
                                {name: "firstName", content: principal.firstName},
                                {name: "link", content: url.protocol + "//" + url.host.replace(/:.*/, '') +
                                    (url.port > 1000 ? ':' + url.port : '') +
                                    "?email=" + encodeURIComponent(newEmail) +
                                    "&code=" + principal.validateEmailCode + "#verify_email"},
                                {name: "verificationCode", content: principal.validateEmailCode}
                            ]);

                        log("Changed email " + oldEmail + " to " + newEmail);

                        return page ? this.setPage(page) : false;

                    }.bind(this));
                }},
            resendChangeEmailValidationCode: {
                on: "server",
                validate: function () {
                    return this.validate(document.getElementById('changeEmailFields'))},
                body: function(url)
                {
                    url = urlparser.parse(url, true);
                    var principal = this[principalProperty];
                    this.sendEmail("email_verify", principal.email, principal.firstName + " " + principal.lastName, [
                        {name: "email", content: principal.email},
                        {name: "firstName", content: principal.firstName},
                        {name: "link", content: url.protocol + "//" + url.host.replace(/:.*/, '') +
                            (url.port > 1000 ? ':' + url.port : '') +
                            "?email=" + encodeURIComponent(principal.email) +
                            "&code=" + principal.validateEmailCode + "#verify_email"},
                        {name: "verificationCode", content: principal.validateEmailCode}
                    ]);

                    log("Resent email validation code to " + principal.email);
                }},
            /**
             * Change the password for a logged in user verifying old password
             */
            changePassword: {
                on: "server",
                validate: function () {return this.validate(document.getElementById('changePasswordFields'))},
                body: function(page)
                {
                    return this[principalProperty].authenticate(this.password, true).then(function()
                    {
                        return this[principalProperty].establishPassword(this.newPassword).then(function ()
                        {
                            log("Changed password for " + this[principalProperty].email);

                            this.sendEmail("password_changed",
                                this[principalProperty].email, this[principalProperty].firstName,
                                [
                                    {name: "firstName", content: this[principalProperty].firstName}
                                ]);

                            return page ? this.setPage(page) : Q(true);

                        }.bind(this))

                    }.bind(this));
                }},

            /**
             * Request that an email be sent with a password change link
             */
            publicResetPassword: {
                on: "server",
                validate: function () {return this.validate(document.getElementById('publicResetPasswordFields'))},
                body: function(url, page)
                {
                    url = urlparser.parse(url, true);
                    log(1, "Request password reset for " + this.email);
                    return Principal.getFromPersistWithQuery({email: this.email}).then(function (principals)
                    {
                        if (principals.length < 1)
                            throw {code: "invalid_email", text:"Incorrect email"};
                        var principal = principals[0];

                        return principal.setPasswordChangeHash().then (function (token)
                        {
                            this.sendEmail("password_reset",
                                this.email, principal.firstName, [
                                    {name: "link", content: url.protocol + "//" + url.host.replace(/:.*/, '') +
                                        (url.port > 1000 ? ':' + url.port : '') +
                                        "?email=" + encodeURIComponent(this.email) +
                                        "&token=" + token + "#reset_password_from_code"},
                                    {name: "firstName", content: principal.firstName}
                                ]);

                            return page ? this.setPage(page) : Q(true);

                        }.bind(this));

                    }.bind(this))
                }},

            /**
             * Change the password given the token and log the user in
             * Token was generated in publicResetPassword and kept in principal entity to verify
             */
            publicChangePasswordFromToken: {
                on: "server",
                validate: function () {return this.validate(document.getElementById('publicChangePasswordFromTokenFields'))},
                body: function(page)
                {
                    var principal;

                    return Principal.getFromPersistWithQuery({email:this.email}).then(function (principal)
                    {
                        if (principal.length < 1)
                            throw {code: "ivalid_password_change_token",
                                text: "Invalid password change link - make sure you copied correctly from the email"};

                        principal = principal[0];
                        return principal.consumePasswordChangeToken(this.passwordChangeHash, this.newPassword);

                    }.bind(this)).then(function ()
                    {
                        return principal.establishPassword(this.newPassword)

                    }.bind(this)).then(function ()
                    {
                        this.setLoggedInState(principal)
                        return page ? this.setPage(page) : false;

                    }.bind(this))
                }},

            /**
             * Verify the email code and log the user in
             */
            publicVerifyEmailFromCode: {on: "server", body: function(page)
            {
                var principal;

                return Principal.getFromPersistWithQuery({email:this.email}).then(function (principals)
                {
                    if (principals.length < 1)
                        throw {code: "invalid_email_verification_code",
                            text: "Invalid verification link - make sure you copied correctly from the email"};

                    principal = principals[0];
                    return principal.consumeEmailVerificationCode(this.verifyEmailCode);

                }.bind(this)).then(function ()
                {
                    this.setLoggedInState(principal)
                    return page ? this.setPage(page) : false;

                }.bind(this))
            }},

            /**
             * Verify the email code assuming principal already in controller
             */
            privateVerifyEmailFromCode: {on: "server", body: function(verifyEmailCode)
            {
                var principal = this[principalProperty];
                try {
                    return principal.consumeEmailVerificationCode(verifyEmailCode);
                } catch (e) {
                    return Q(false);
                }
            }}
        });
}