import * as Q from 'q';
import * as _ from 'underscore';
import * as crypto from 'crypto';
import * as urlparser from 'url';
import {Supertype, supertypeClass, property, remote} from 'amorphic';
import * as objectTemplate from 'amorphic';

/*
 * SecurityContext can be retrieved using getSecurityContext on any object to
 * find out who is logged in and what there roll is
 
objectTemplate['globalInject'](function (obj) {
    obj.getSecurityContext = function () {
        return objectTemplate['controller'].securityContext || new SecurityContext();
    }
});
*/

function validateEmail () {return this.__objectTemplate__.config.userman.validateEmail || 0};
function validateEmailAndLogin () {return this.__objectTemplate__.config.userman.validateEmailAndLogin;}
function passwordChangeExpiresHours () {return this.__objectTemplate__.config.userman.passwordChangeExpiresHours;}
function validateEmailForce () {return this.__objectTemplate__.config.userman.validateEmailForce;}
function defaultEmail () {return this.__objectTemplate__.config.userman.defaultEmail}
function defaultPassword () {return this.__objectTemplate__.config.userman.defaultPassword}
function defaultRole () {return this.__objectTemplate__.config.userman.defaultRole}
function validateEmailHumanReadable () {return this.__objectTemplate__.validateEmailHumanReadable}
function maxLoginAttempts () {return this.__objectTemplate__.config.userman.maxLoginAttempts || 0};
function maxLoginPeriodMinutes () {return (this.__objectTemplate__.config.userman.maxLoginPeriodMinutes || 10) * 60};
function defaultAdminRole  () {return this.__objectTemplate__.config.userman.defaultAdminRole};
function maxPreviousPasswords  () {return this.__objectTemplate__.config.userman.maxPreviousPasswords};
function temporaryPasswordExpiresMinutes  () {return  this.__objectTemplate__.config.userman.temporaryPasswordExpiresMinutes};
function deferEmailChange  () {return this.__objectTemplate__.config.userman.deferEmailChange};
function passwordExpiresMinutes () {return this.__objectTemplate__.config.userman.passwordExpiresMinutes;}

function log(message) {
    this.__objectTemplate__.logger.info(message);
}


function filterProperty () {return this.__objectTemplate__.config.filterProperty}
function filterValue () {return this.__objectTemplate__.config.filterProperty}

// Add the property filter on a query
function queryFilter(query) {
    if (filterProperty.call(this) && filterValue.call(this)) {
        query[filterProperty.call(this)] = filterValue.call(this);
    }
    return query;
}
// Add the property value to an object (principal)
function insertFilter(obj) {
    if (filterProperty.call(this) && filterValue.call(this)) {
        obj[filterProperty.call(this)] = filterValue.call(this);
    }
}

@supertypeClass
export class SecurityContext extends Supertype  {

    @property({toServer: false, getType: () => {return AuthenticatedPrincipal}})
    principal: AuthenticatedPrincipal;

    @property({toServer: false})
    role: string;

    @property({toServer: false})
    defaultAdminRole: string;

    constructor (principal, role) {
        super();
        this.principal = principal;
        this.role = role;
        this.defaultAdminRole = defaultAdminRole.call(this);
    }

    isLoggedIn () {
        return !!this.role;
    }
    isAdmin () {
        return this.isLoggedIn() && this.principal.role == this.defaultAdminRole;
    }
}

@supertypeClass
export class AuthenticatedPrincipal extends Supertype  {

   // These secure elements are NEVER transmitted

    @property({toServer: false})
    email: string = '';

    @property({toServer: false})
    newEmail: string = '';

    @property({toServer: false})
    firstName: string = '';

    @property({toServer: false})
    lastName: string = '';

    @property({toServer: false})
    emailValidated: boolean = false;

    @property({toServer: false})
    suspended: boolean = false;

    @property({toServer: false})
    lockedOut: boolean = false;

    @property({toServer: false, toClient: false, type: Date})
    unsuccesfulLogins: Array<Date> = [];

    @property({toServer: false})
    passwordExpires: Date;

    @property({toServer: false})
    mustChangePassword: boolean = false;

    @property({toServer: false, toClient: false, type: String})
    previousSalts: Array<string> = [];

    @property({toServer: false, toClient: false, type: String})
    previousHashes: Array<String> = [];

    @property({toServer: false, values: {
        user:               'User',             // A normal user
        defaultAdminRole:   'Administrator'    // An administrative user})
    }})
    role:  string = 'user';

    @property({toServer: false})
    securityContext:  SecurityContext;

    // These are never received.  You can mess with your passwork assuming you are logged in but never see it

    @property({toClient: false, toServer: false})
    passwordHash: string;

    @property({toClient: false, toServer: false})
    passwordSalt: string;

    @property({toClient: false, toServer: false})
    passwordChangeHash: string = '';

    @property({toClient: false, toServer: false})
    passwordChangeSalt: string = '';

    @property({toClient: false, toServer: false})
    passwordChangeExpires: Date;

    @property({toClient: false, toServer: false})
    validateEmailCode: string;

    @remote()
    roleSet (role) {
        if (this.securityContext.role == defaultAdminRole.call(this))
            this.role = role;
        else
            throw {code: "role_change", text: "You cannot change roles"};
    }

    @remote()
    suspendUser (suspended) {
        if (this.securityContext.role == defaultAdminRole.call(this) && (this.role != defaultAdminRole.call(this)))
            this.suspended = suspended;
        else
            throw {code: "suspend_change", text: "You cannot suspend/resume"};
        return this.persistSave();
    }

    @remote()
    changeEmail (email) {
        if (this.securityContext.role == defaultAdminRole.call(this) && (this.role != defaultAdminRole.call(this)))
            return AuthenticatedPrincipal.getFromPersistWithQuery(queryFilter.call(this, {email: email})).then(function (principals) {
                if (principals.length > 0)
                    throw {code: "email_change_exists", text: "Email already exists"};
                this.email = email;
                return this.persistSave();
            }.bind(this));
        else
            throw {code: "email_change", text: "You cannot change email"};
    }


    @remote()
    setRoleForUser (role) {
        this.roleSet(role);
        return this.persistSave();
    }

    isAdmin () {
        return this.role == defaultAdminRole.call(this);
    }

    /**
     * Create a password hash and save the object
     *
     * @param password
     * @returns {*} promise (true) when done
     * throws an exception if the password does not meet password rules
     */

    establishPassword (password, expires, noValidate, forceChange) {
        if (!noValidate)
            this.validateNewPassword(password);

        var promises = [];
        if (maxPreviousPasswords.call(this))
            for (var ix = 0; ix < this.previousHashes.length; ++ix)
                (function () {
                    var closureIx = ix;
                    promises.push(this.getHash(password, this.previousSalts[closureIx]).then(function (hash) {
                        if (this.previousHashes[closureIx] === hash)
                            throw {code: "last3", text: "Password same as one of last " + maxPreviousPasswords.call(this)};
                        return Q(true);
                    }.bind(this)));
                }.bind(this))()
        return Q.all(promises).then(function ()
        {
            // Get a random number as the salt
            return this.getSalt().then(function (salt) {
                this.passwordSalt = salt;
                this.passwordChangeHash = "";

                // Create a hash of the password with the salt
                return this.getHash(password, salt);

            }.bind(this)).then(function (hash) {
                // Save this for verification later
                this.passwordHash = hash;
                while (this.previousSalts.length > maxPreviousPasswords.call(this))
                    this.previousSalts.splice(0, 1);
                while (this.previousHashes.length > maxPreviousPasswords.call(this))
                    this.previousHashes.splice(0, 1);
                this.previousSalts.push(this.passwordSalt);
                this.previousHashes.push(this.passwordHash);
                this.passwordExpires = expires;
                this.mustChangePassword = forceChange || false;
                return this.persistSave();
            }.bind(this));

        }.bind(this));
    }

    /**
     * Check password rules for a new password
     *
     * @param password
     * @return {*}
     */
    validateNewPassword (password) {
        if (password.length < 6 || password.length > 30 || !password.match(/[A-Za-z]/) || !password.match(/[0-9]/))

            throw {code: "password_composition",
                text: "Password must be 6-30 characters with at least one letter and one number"};
    }

    /**
     * Return a password hash
     *
     * @param password
     * @param salt
     * @return {*}
     */

    getHash (password, salt) {
        return Q.ninvoke(crypto, 'pbkdf2', password, salt, 10000, 64).then(function (whyAString : string) {
            return Q((new Buffer(whyAString, 'binary')).toString('hex'));
        });
    }

    /**
     * Get a secure random string for the salt
     *
     * @return {*}
     */
    getSalt () {
        return Q.ninvoke(crypto, 'randomBytes', 64).then(function (buf : Buffer) {
            return Q(buf.toString('hex'));
        });
    }

    /*
     * Make registration pending verification of a code usually sent by email
     */
    setEmailVerificationCode () {
        this.emailValidated = false;
        if (validateEmailHumanReadable.call(this)) {
            this.validateEmailCode = Math.random().toString().substr(2,4);
            return this.persistSave();
        } else
            return this.getSalt().then(function (salt) {
                this.validateEmailCode = salt.substr(10, 6);
                return this.persistSave();

            }.bind(this));
    }

    /*
     * Verify the email code passed in and reset the principal record to allow registration to proceed
     */
    consumeEmailVerificationCode (code) {
        if (code != this.validateEmailCode)
            throw {code: "inavlid_validation_link", text: "Incorrect email validation link"}

        //this.validateEmailCode = false;
        this.emailValidated = true;
        return this.persistSave();
    }

    /**
     * Create a one-way hash for changing passwords
     * @returns {*}
     */
    setPasswordChangeHash () {
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
            (passwordChangeExpiresHours.call(this) || 24) * 60 * 60 * 1000));
            return this.persistSave();
        }.bind(this)).then(function () {
            return Q(token);
        }.bind(this));
    }

    /**
     * Consume a password change token and change the password
     *
     * @param token
     * @returns {*}
     */
    consumePasswordChangeToken (token, newPassword) {
        if (!this.passwordChangeHash)
            throw {code: "password_reset_used", text: "Password change link already used"};
        return this.getHash(token, this.passwordChangeSalt).then(function (hash) {
            if (this.passwordChangeHash != hash)
                throw {code: "invalid_password_change_link", text: "Incorrect password change link"};
            if (this.passwordChangeExpires.getTime() < (new Date()).getTime())
                throw {code: "password_change_link_expired", text: "Password change link expired"};
            return this.establishPassword(newPassword);
        }.bind(this));
    }

    /**
     * Verify a password on login (don't reveal password vs. user name is bad)
     *
     * @param password
     * @returns {*}
     */
    authenticate (password, loggedIn, novalidate) {
        if (!novalidate && this.validateEmailCode && validateEmailForce.call(this))

            throw {code: "registration_unverified",
                text: "Please click on the link in your verification email to activate this account"};

        if (this.lockedOut)
            throw {code: "locked out", text: "Please contact your security administrator"};

        if (this.passwordExpires && (new Date()).getTime() > this.passwordExpires.getTime())
            throw {code: "loginexpired", text: "Your password has expired"};

        return this.getHash(password, this.passwordSalt).then(function (hash) {
            if (this.passwordHash !== hash) {
                return this.badLogin().then(function () {
                    this.persistSave();
                    throw loggedIn ?
                    {code: "invalid_password", text: "Incorrect password"} :
                    {code: "invalid_email_or_password", text: "Incorrect email or password"};
                }.bind(this));
            } else {
            }
            return Q(true);

        }.bind(this))
    }

    badLogin () {
        if (maxLoginAttempts.call(this)) {
            this.unsuccesfulLogins.push(new Date());
            this.unsuccesfulLogins = _.filter(this.unsuccesfulLogins, function (attempt) {
                return ((new Date(attempt)).getTime() > ((new Date()).getTime() - 1000 * 60 * maxLoginPeriodMinutes.call(this)));
            });
            if (this.unsuccesfulLogins.length > maxLoginAttempts.call(this)) {
                if (this.role != defaultAdminRole.call(this)) {
                    this.lockedOut = true;
                }
                return Q.delay(10000)
            }
            return Q.delay(1000);
        } else
            return Q.delay(2000)
    }

}


@supertypeClass
export abstract class AuthenticatingController extends Supertype  {

    @property({length: 50, rule: ["name", "required"]})
    firstName: string = '';

    @property({length: 50, rule: ["name", "required"]})
    lastName: string = '';

    @property({length: 50, rule: ["text", "email", "required"]})
    email: string = '';

    @property({length: 50, rule: ["text", "email", "required"]})
    newEmail: string = '';

    // Secure variables never leaked to the client

    @property({toClient: false})
    password: string = '';

    @property({toClient: false, rule:["required"]})
    confirmPassword: string = '';

    @property({toClient: false, rule:["required"]})
    newPassword: string = '';


    @property({toClient: false})
    passwordChangeHash: string = '';

    @property({toClient: false})
    verifyEmailCode: string = '';

    @property({toServer: false})
    loggedIn: boolean = false;

    @property({toServer: false})
    loggedInRole: string;

    isAdmin () {
        return this.loggedIn && this.loggedInRole == defaultAdminRole.call(this);
    }

    @property({toServer: false})
    securityContext:  SecurityContext;
    
    abstract setPrincipal(principal: AuthenticatedPrincipal);
    abstract getPrincipal() : AuthenticatedPrincipal;
        
    isLoggedIn () {
        return !!this.loggedIn;
    }

    createAdmin () {
        AuthenticatedPrincipal.countFromPersistWithQuery({role: defaultAdminRole.call(this)}).then(function (count) {
            if (count == 0) {
                var admin = new AuthenticatedPrincipal();
                admin.email = defaultEmail.call(this) || "amorphic@amorphic.com";
                admin.firstName = "Admin";
                admin.lastName = "User";
                admin.role = defaultAdminRole.call(this);
                this.amorphicate(admin);
                return admin.establishPassword(defaultPassword.call(this) || "admin", null, true, true);
            } else
                return Q(false);
        }.bind(this));
    }

    /**
     * Create a new principal if one does not exist. This method is used by the currently logged in user to create
     * new users. The principal info comes from the an object which should have the following properties:
     *
     * firstName, lastName, email, newPassword, confirmPassword, role
     *
     * Also used to reset a password
     */
    @remote({validate: function(){return this.validate(document.getElementById('publicRegisterFields'))}})

    createNewAdmin (adminUser, url, pageConfirmation?, pageInstructions?, reset?) {

        // Check for security context of security admin
        if(this.loggedInRole !== defaultRole.call(this)){
            throw {code: 'cannotcreateadmin', text: "Only a security admin can create users"};
        }
        if (adminUser.newPassword != adminUser.confirmPassword)
            throw {code: 'passwordmismatch', text: "Password's are not the same"};

        var principal;

        url = url ? urlparser.parse(url, true) : "";
        return AuthenticatedPrincipal.getFromPersistWithQuery({email: adminUser.email}).then( function (principals)
        {
            if (reset) {
                if (principals.length == 0)
                    throw {code: "email_notfound", text: "Can't find this user"};
                principal = principals[0];
            } else {
                if (principals.length > 0)
                    throw {code: "email_registered", text:"This email is already registered"};
                principal = new AuthenticatedPrincipal();
            }
            this.amorphicate(principal);

            // this[principalProperty] = this[principalProperty] || new Principal();
            principal.lockedOut = false;
            if (!reset) {
                principal.email = adminUser.email;
                principal.firstName = adminUser.firstName;
                principal.lastName = adminUser.lastName;
                principal.role = adminUser.role;
            }
            return principal.establishPassword(adminUser.newPassword,
                principal.role == defaultAdminRole.call(this) ? null :
                    new Date((new Date()).getTime() + temporaryPasswordExpiresMinutes.call(this) * 1000 * 60), false, true);

        }.bind(this)).then( function() {
            if (validateEmail.call(this))
                return principal.setEmailVerificationCode();
            else {
                return Q();
            }
        }.bind(this)).then (function ()
        {
            if (url)
                this.sendEmail(validateEmail.call(this) ? "register_verify": "register",
                    principal.email, this.firstName + " " + this.lastName, [
                        {name: "firstName", content: this.firstName},
                        {name: "email", content: this.email},
                        {name: "link", content: url.protocol + "//" + url.host.replace(/:.*/, '') +
                        (url.port > 1000 ? ':' + url.port : '') +
                        "?email=" + encodeURIComponent(this.email) +
                        "&code=" + principal.validateEmailCode + "#verify_email"}
                    ]);
            if (validateEmail.call(this) && pageInstructions)
                return this.setPage(pageInstructions);
            if (!validateEmail.call(this) && pageConfirmation)
                return this.setPage(pageConfirmation);
            return Q(principal);
        }.bind(this))
    }

    /**
     * Create a new principal if one does not exist and consider ourselves logged in
     *
     * @param password
     */
    @remote({validate: function () {
        return this.validate(document.getElementById('publicRegisterFields'));
    }})
    publicRegister (url, pageConfirmation?, pageInstructions?) {
        if (this.newPassword != this.confirmPassword)
            throw {code: 'passwordmismatch', text: "Password's are not the same"};

        var principal;

        url = urlparser.parse(url, true);
        return AuthenticatedPrincipal.countFromPersistWithQuery(
            queryFilter.call(this, {email: { $regex: new RegExp("^" + this.email.toLowerCase().replace(/([^0-9a-zA-Z])/g, "\\$1") + '$'), $options: 'i' }})
        ).then( function (count)
        {
            if (count > 0)
                throw {code: "email_registered", text:"This email already registered"};

            this.setPrincipal(this.getPrincipal() || new AuthenticatedPrincipal());
            principal = this.getPrincipal();
            this.amorphicate(principal);
            principal.email = this.email;
            principal.firstName = this.firstName;
            principal.lastName = this.lastName;
            insertFilter.call(this, principal);
            return principal.establishPassword(this.newPassword);

        }.bind(this)).then( function() {
            if (validateEmail.call(this))
                return principal.setEmailVerificationCode();
            else
                return Q(true);
        }.bind(this)).then( function () {
            if (!validateEmail.call(this) || validateEmailAndLogin.call(this))
                this.setLoggedInState(principal);
            this.sendEmail(validateEmail.call(this) ? "register_verify": "register",
                principal.email, principal.firstName + " " + principal.lastName, [
                    {name: "firstName", content: this.firstName},
                    {name: "email", content: this.email},
                    {name: "link", content: url.protocol + "//" + url.host.replace(/:.*/, '') +
                    (url.port > 1000 ? ':' + url.port : '') +
                    "?email=" + encodeURIComponent(this.email) +
                    "&code=" + principal.validateEmailCode + "#verify_email"},
                    {name: "verificationCode", content: this.getPrincipal().validateEmailCode}

                ]);
            if (validateEmail.call(this) && pageInstructions)
                return this.setPage(pageInstructions);
            if (!validateEmail.call(this) && pageConfirmation)
                return this.setPage(pageConfirmation);

        }.bind(this))
    }

    /**
     * login the user
     */
    @remote({validate: function () {return this.validate(document.getElementById('publicLoginFields'))}})
    publicLogin (page?, forceChange?) {
        var principal;
        if (this.loggedIn)
            throw {code: "already_loggedin", text: "Already logged in"};

        var query = AuthenticatedPrincipal.getFromPersistWithQuery(
            queryFilter.call(this, {email: { $regex: new RegExp("^" + this.email.toLowerCase().replace(/([^0-9a-zA-Z])/g, "\\$1") + '$'), $options: 'i' }}),
                null, null, null, true);
            return query.then(function (principals) {
                if (principals.length == 0 || principals[0].suspended) {
                    log.call(this, "Log In attempt for " + this.email + " failed (invalid email)");
                    throw {code: "invalid_email_or_password",
                        text: "Incorrect email or password"};
                }
                principal = principals[0];
                this.amorphicate(principal);
                return principal.authenticate(this.password);
            }.bind(this)).then( function() {
                return AuthenticatedPrincipal.getFromPersistWithId(principal._id);
            }.bind(this)).then( function(p) {
                principal = p;
                this.amorphicate(principal);
                forceChange = forceChange || principal.mustChangePassword;
                if (forceChange && !this.newPassword)
                    throw {code: "changePassword", text: "Please change your password"};
                return forceChange ? this.changePasswordForPrincipal(principal) : Q(true);
            }.bind(this)).then( function (status) {
                if (status)
                    this.setLoggedInState(principal);
                return page ? this.setPage(page) : Q(true);
            }.bind(this))
    }

    /**
     * login the user with changed email. Also verify email code
     */
    @remote({validate: function () {return this.validate(document.getElementById('publicLoginFields'))}})
    publicLoginWithNewEmail (page?)
    {
        var principal;

        return AuthenticatedPrincipal.getFromPersistWithQuery(
            queryFilter.call(this, {newEmail: { $regex: new RegExp("^" + this.email.toLowerCase().replace(/([^0-9a-zA-Z])/g, "\\$1") + '$', "i") }}),
            null, null, null, true
        ).then( function (principals) {
            if (principals.length == 0) {
                log.call(this, "Log In attempt for " + this.email + " failed (invalid email)");
                throw {code: "invalid_email_or_password",
                    text: "Incorrect email or password"};
            }
            principal = principals[0];
            this.amorphicate(principal);
            return principal.authenticate(this.password);
        }.bind(this)).then( function() {
            return AuthenticatedPrincipal.getFromPersistWithId(principal._id);
        }.bind(this)).then( function(p) {
            principal = p;
            this.amorphicate(principal);
            if (principal.mustChangePassword && !this.newPassword)
                throw {code: "changePassword", text: "Please change your password"};
            return principal.mustChangePassword ? this.changePasswordForPrincipal(principal) : Q(true);
        }.bind(this)).then( function (status) {
            return principal.consumeEmailVerificationCode(this.verifyEmailCode);
        }.bind(this)).then(function(){
            this.setLoggedInState(principal);

            principal.email = this.email;
            principal.newEmail = ""; // No need to track the changed email anymore
            principal.persistSave();

            // Send an email changed confirmation email
            this.sendEmail("confirm_emailchange", this.email, principal.email,
                principal.firstName + " " + principal.lastName, [
                    {name: "email", content: this.email},
                    {name: "firstName", content: principal.firstName}
                ]);

            return page ? this.setPage(page) : Q(true);
        }.bind(this))
    }

    /**
     *  Set up all fields to indicate logged in
     */
    setLoggedInState (principal)
    {
        this.loggedIn = true;
        this.loggedInRole = principal.role;
        this.setPrincipal(principal);

        // One way so you can't spoof from client
        this.securityContext = new SecurityContext(principal, principal.role);
    }

    /**
     *  Set up all fields to indicate logged out
     */
    setLoggedOutState ()
    {
        this.setPrincipal(null);
        this.loggedIn = false;
        this.loggedInRole = null;
        this.securityContext = null;
    }

    /*
     * logout the current user
     */
    @remote()
    publicLogout ()
    {
        log.call(this, "Customer " + this.email + " logged out");
        this.setLoggedOutState();
    }

    /**
     * change an email address for a logged in user
     */
    @remote({validate: function () {return this.validate(document.getElementById('changeEmailFields'))}})
    changeEmail (page, url)
    {
        url = urlparser.parse(url, true);
        var principal = this.getPrincipal();
        var oldEmail = principal.email;
        var newEmail = this.newEmail;

        return Q(true).then(function () {
            return principal.authenticate(this.password, null, true);
        }.bind(this)).then (function () {
            return AuthenticatedPrincipal.countFromPersistWithQuery(queryFilter.call(this, {email: newEmail}))
        }.bind(this)).then(function (count) {
            if (count > 0)
                throw {code: "email_registered", text:"This email already registered"};
        }.bind(this)).then( function() {
            if (validateEmail.call(this))
                return principal.setEmailVerificationCode();
            else {
                return Q(false);
            }
        }.bind(this)).then( function() {
            if (!deferEmailChange.call(this))
                this.email = newEmail;

            principal.newEmail = newEmail;
            principal.persistSave();

            // Send an email to old email address which is purely informational
            this.sendEmail("email_changed", oldEmail, principal.email,
                principal.firstName + " " + principal.lastName, [
                    {name: "oldEmail", content: oldEmail},
                    {name: "email", content: newEmail},
                    {name: "firstName", content: principal.firstName}
                ]);

            // Send an email to new email address asking to verify the new email
            // address
            this.sendEmail(validateEmail.call(this) ? "email_changed_verify" : "email_changed",
                newEmail,  principal.firstName + " " + principal.lastName, [
                    {name: "oldEmail", content: oldEmail},
                    {name: "email", content: newEmail},
                    {name: "firstName", content: principal.firstName},
                    {name: "link", content: url.protocol + "//" + url.host.replace(/:.*/, '') +
                    (url.port > 1000 ? ':' + url.port : '') +
                    "?email=" + encodeURIComponent(newEmail) +
                    "&code=" + principal.validateEmailCode + (deferEmailChange.call(this) ? "#verify_email_change" : "#verify_email")},
                    {name: "verificationCode", content: principal.validateEmailCode}
                ]);

            log.call(this, "Changed email " + oldEmail + " to " + newEmail);

            return page ? this.setPage(page) : Q(true);

        }.bind(this));
    }
    abstract sendEmail (slug, email, name, emails : Array<any>)
    @remote({validate: function () {return this.validate(document.getElementById('changeEmailFields'))}})
    resendChangeEmailValidationCode (url)
    {
        url = urlparser.parse(url, true);
        var principal = this.getPrincipal();
        this.sendEmail("email_verify", principal.email, principal.firstName + " " + principal.lastName, [
            {name: "email", content: principal.email},
            {name: "firstName", content: principal.firstName},
            {name: "link", content: url.protocol + "//" + url.host.replace(/:.*/, '') +
            (url.port > 1000 ? ':' + url.port : '') +
            "?email=" + encodeURIComponent(principal.email) +
            "&code=" + principal.validateEmailCode + "#verify_email"},
            {name: "verificationCode", content: principal.validateEmailCode}
        ]);

        log.call(this, "Resent email validation code to " + principal.email);
    }
    
    /**
     * Change the password for a logged in user verifying old password
     * Also called from login on a force change password so technically you don't have to be logged in
     */
    @remote({validate: function () {return this.validate(document.getElementById('changePasswordFields'))}})
    changePassword (page)
    {
        if (!this.loggedIn)
            throw {code: "not_loggedin", text:"Not logged in"};
        return this.changePasswordForPrincipal(this.getPrincipal(), page);
    }

    changePasswordForPrincipal(principal, page?)
    {
        return principal.authenticate(this.password, true).then(function()
        {
            return principal.establishPassword(this.newPassword,
                passwordExpiresMinutes.call(this) ?
                    new Date((new Date()).getTime() + passwordExpiresMinutes.call(this) * 1000 * 60) : null).then(function ()
            {
                log.call(this, "Changed password for " + principal.email);
                if (this.sendEmail)
                    this.sendEmail("password_changed",
                        principal.email, principal.firstName,
                        [
                            {name: "firstName", content: principal.firstName}
                        ]);

                return page ? this.setPage(page) : Q(true);

            }.bind(this))

        }.bind(this));
    }
    
    /**
     * Request that an email be sent with a password change link
     */
    @remote({validate: function () {return this.validate(document.getElementById('publicResetPasswordFields'))}})
    publicResetPassword (url, page)
    {
        url = urlparser.parse(url, true);
        log.call(this, "Request password reset for " + this.email);
        return AuthenticatedPrincipal.getFromPersistWithQuery(queryFilter.call(this, {email: this.email}), null, null, null, true).then(function (principals)
        {
            if (principals.length < 1)
                throw {code: "invalid_email", text:"Incorrect email"};
            var principal = principals[0];
            this.amorphicate(principal);

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
    }

    /**
     * Change the password given the token and log the user in
     * Token was generated in publicResetPassword and kept in principal entity to verify
     */
    @remote({validate: function () {return this.validate(document.getElementById('publicChangePasswordFromTokenFields'))}})
    publicChangePasswordFromToken (page)
    {
        var principal;

        return AuthenticatedPrincipal.getFromPersistWithQuery(queryFilter.call(this, {email:this.email}), null, null, null, true).then(function (principals)
        {
            if (principals.length < 1)
                throw {code: "ivalid_password_change_token",
                    text: "Invalid password change link - make sure you copied correctly from the email"};

            principal = principals[0];
            this.amorphicate(principal);
            return principal.consumePasswordChangeToken(this.passwordChangeHash, this.newPassword);

        }.bind(this)).then( function() {
            return AuthenticatedPrincipal.getFromPersistWithId(principal._id);
        }.bind(this)).then( function(p) {
            principal = p;
            this.amorphicate(principal);
            return principal.establishPassword(this.newPassword)

        }.bind(this)).then(function () {
            this.setLoggedInState(principal)

            log.call(this, "Changed password for " + principal.email);
            if (this.sendEmail){
                this.sendEmail("password_changed", principal.email, principal.firstName, [
                    {name: "firstName", content: principal.firstName}
                ]);
            }

            return page ? this.setPage(page) : Q(true);
        }.bind(this))
    }

    /**
     * Verify the email code
     */
    @remote()
    publicVerifyEmailFromCode (page?)
    {
        var principal;

        return AuthenticatedPrincipal.getFromPersistWithQuery(queryFilter.call(this, {email:this.email}), null, null, null, true).then(function (principals)
        {
            if (principals.length < 1)
                throw {code: "invalid_email_verification_code",
                    text: "Invalid verification link - make sure you copied correctly from the email"};

            principal = principals[0];
            this.amorphicate(principal);
            return principal.consumeEmailVerificationCode(this.verifyEmailCode);

        }.bind(this)).then(function ()
        {
            return page ? this.setPage(page) : Q(true);

        }.bind(this))
    }

    /**
     * Verify the email code assuming principal already in controller
     */
    @remote()
    privateVerifyEmailFromCode (verifyEmailCode)
    {
        var principal = this.getPrincipal();
        try {
            return principal.consumeEmailVerificationCode(verifyEmailCode);
        } catch (e) {
            return Q(false);
        }
    }
}
