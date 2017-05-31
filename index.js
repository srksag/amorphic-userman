"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = y[op[0] & 2 ? "return" : op[0] ? "throw" : "next"]) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [0, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
var Q = require("q");
var _ = require("underscore");
var crypto = require("crypto");
var urlparser = require("url");
var amorphic_1 = require("amorphic");
require("es6-promise");
/*
 * SecurityContext can be retrieved using getSecurityContext on any object to
 * find out who is logged in and what there roll is

objectTemplate['globalInject'](function (obj) {
    obj.getSecurityContext = function () {
        return objectTemplate['controller'].securityContext || new SecurityContext();
    }
});
*/
function validateEmail() { return this.__objectTemplate__.config.userman.validateEmail || 0; }
;
function validateEmailAndLogin() { return this.__objectTemplate__.config.userman.validateEmailAndLogin; }
function passwordChangeExpiresHours() { return this.__objectTemplate__.config.userman.passwordChangeExpiresHours; }
function validateEmailForce() { return this.__objectTemplate__.config.userman.validateEmailForce; }
function defaultEmail() { return this.__objectTemplate__.config.userman.defaultEmail; }
function defaultPassword() { return this.__objectTemplate__.config.userman.defaultPassword; }
function defaultRole() { return this.__objectTemplate__.config.userman.defaultRole; }
function validateEmailHumanReadable() { return this.__objectTemplate__.validateEmailHumanReadable; }
function maxLoginAttempts() { return this.__objectTemplate__.config.userman.maxLoginAttempts || 0; }
;
function maxLoginPeriodMinutes() { return (this.__objectTemplate__.config.userman.maxLoginPeriodMinutes || 10) * 60; }
;
function defaultAdminRole() { return this.__objectTemplate__.config.userman.defaultAdminRole; }
;
function maxPreviousPasswords() { return this.__objectTemplate__.config.userman.maxPreviousPasswords; }
;
function temporaryPasswordExpiresMinutes() { return this.__objectTemplate__.config.userman.temporaryPasswordExpiresMinutes; }
;
function deferEmailChange() { return this.__objectTemplate__.config.userman.deferEmailChange; }
;
function passwordExpiresMinutes() { return this.__objectTemplate__.config.userman.passwordExpiresMinutes; }
function log(message) {
    this.__objectTemplate__.logger.info(message);
}
function filterProperty() { return this.__objectTemplate__.config.filterProperty; }
function filterValue() { return this.__objectTemplate__.config.filterProperty; }
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
var SecurityContext = (function (_super) {
    __extends(SecurityContext, _super);
    function SecurityContext(principal, role) {
        var _this = _super.call(this) || this;
        if (_this.amorphicLeaveEmpty)
            return _this;
        _this.principal = principal;
        _this.role = role;
        _this.defaultAdminRole = defaultAdminRole.call(principal);
        return _this;
    }
    SecurityContext.prototype.isLoggedIn = function () {
        return !!this.role;
    };
    SecurityContext.prototype.isAdmin = function () {
        return this.isLoggedIn() && this.principal.role == this.defaultAdminRole;
    };
    return SecurityContext;
}(amorphic_1.Remoteable(amorphic_1.Persistable(amorphic_1.Supertype))));
__decorate([
    amorphic_1.property({ toServer: false, getType: function () { return AuthenticatedPrincipal; } }),
    __metadata("design:type", AuthenticatedPrincipal)
], SecurityContext.prototype, "principal", void 0);
__decorate([
    amorphic_1.property({ toServer: false }),
    __metadata("design:type", String)
], SecurityContext.prototype, "role", void 0);
__decorate([
    amorphic_1.property({ toServer: false }),
    __metadata("design:type", String)
], SecurityContext.prototype, "defaultAdminRole", void 0);
SecurityContext = __decorate([
    amorphic_1.supertypeClass,
    __metadata("design:paramtypes", [Object, Object])
], SecurityContext);
exports.SecurityContext = SecurityContext;
var AuthenticatedPrincipal = AuthenticatedPrincipal_1 = (function (_super) {
    __extends(AuthenticatedPrincipal, _super);
    function AuthenticatedPrincipal() {
        // These secure elements are NEVER transmitted
        var _this = _super !== null && _super.apply(this, arguments) || this;
        _this.email = '';
        _this.newEmail = '';
        _this.firstName = '';
        _this.lastName = '';
        _this.emailValidated = false;
        _this.suspended = false;
        _this.lockedOut = false;
        _this.unsuccesfulLogins = [];
        _this.mustChangePassword = false;
        _this.previousSalts = [];
        _this.previousHashes = [];
        _this.role = 'user';
        _this.passwordChangeHash = '';
        _this.passwordChangeSalt = '';
        return _this;
    }
    AuthenticatedPrincipal.prototype.roleSet = function (role) {
        if (this.securityContext.role == defaultAdminRole.call(this))
            this.role = role;
        else
            throw { code: "role_change", text: "You cannot change roles" };
    };
    AuthenticatedPrincipal.prototype.suspendUser = function (suspended) {
        if (this.securityContext.role == defaultAdminRole.call(this) && (this.role != defaultAdminRole.call(this)))
            this.suspended = suspended;
        else
            throw { code: "suspend_change", text: "You cannot suspend/resume" };
        return this.persistSave();
    };
    AuthenticatedPrincipal.prototype.changeEmail = function (email) {
        if (this.securityContext.role == defaultAdminRole.call(this) && (this.role != defaultAdminRole.call(this)))
            return AuthenticatedPrincipal_1.getFromPersistWithQuery(queryFilter.call(this, { email: email })).then(function (principals) {
                if (principals.length > 0)
                    throw { code: "email_change_exists", text: "Email already exists" };
                this.email = email;
                return this.persistSave();
            }.bind(this));
        else
            throw { code: "email_change", text: "You cannot change email" };
    };
    AuthenticatedPrincipal.prototype.setRoleForUser = function (role) {
        this.roleSet(role);
        return this.persistSave();
    };
    /**
     * Create a password hash and save the object
     *
     * @param password
     * @returns {*} promise (true) when done
     * throws an exception if the password does not meet password rules
     */
    AuthenticatedPrincipal.prototype.establishPassword = function (password, expires, noValidate, forceChange) {
        if (!noValidate)
            this.validateNewPassword(password);
        var promises = [];
        if (maxPreviousPasswords.call(this))
            for (var ix = 0; ix < this.previousHashes.length; ++ix)
                (function () {
                    var closureIx = ix;
                    promises.push(this.getHash(password, this.previousSalts[closureIx]).then(function (hash) {
                        if (this.previousHashes[closureIx] === hash)
                            throw { code: "last3", text: "Password same as one of last " + maxPreviousPasswords.call(this) };
                        return Q(true);
                    }.bind(this)));
                }.bind(this))();
        return Q.all(promises).then(function () {
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
    };
    /**
     * Check password rules for a new password
     *
     * @param password
     * @return {*}
     */
    AuthenticatedPrincipal.prototype.validateNewPassword = function (password) {
        if (password.length < 6 || password.length > 30 || !password.match(/[A-Za-z]/) || !password.match(/[0-9]/))
            throw { code: "password_composition",
                text: "Password must be 6-30 characters with at least one letter and one number" };
    };
    /**
     * Return a password hash
     *
     * @param password
     * @param salt
     * @return {*}
     */
    AuthenticatedPrincipal.prototype.getHash = function (password, salt) {
        return Q.ninvoke(crypto, 'pbkdf2', password, salt, 10000, 64).then(function (whyAString) {
            return Q((new Buffer(whyAString, 'binary')).toString('hex'));
        });
    };
    /**
     * Get a secure random string for the salt
     *
     * @return {*}
     */
    AuthenticatedPrincipal.prototype.getSalt = function () {
        return Q.ninvoke(crypto, 'randomBytes', 64).then(function (buf) {
            return Q(buf.toString('hex'));
        });
    };
    /*
     * Make registration pending verification of a code usually sent by email
     */
    AuthenticatedPrincipal.prototype.setEmailVerificationCode = function () {
        this.emailValidated = false;
        if (validateEmailHumanReadable.call(this)) {
            this.validateEmailCode = Math.random().toString().substr(2, 4);
            return this.persistSave();
        }
        else
            return this.getSalt().then(function (salt) {
                this.validateEmailCode = salt.substr(10, 6);
                return this.persistSave();
            }.bind(this));
    };
    /*
     * Verify the email code passed in and reset the principal record to allow registration to proceed
     */
    AuthenticatedPrincipal.prototype.consumeEmailVerificationCode = function (code) {
        if (code != this.validateEmailCode)
            throw { code: "inavlid_validation_link", text: "Incorrect email validation link" };
        //this.validateEmailCode = false;
        this.emailValidated = true;
        return this.persistSave();
    };
    /**
     * Create a one-way hash for changing passwords
     * @returns {*}
     */
    AuthenticatedPrincipal.prototype.setPasswordChangeHash = function () {
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
    };
    /**
     * Consume a password change token and change the password
     *
     * @param token
     * @returns {*}
     */
    AuthenticatedPrincipal.prototype.consumePasswordChangeToken = function (token, newPassword) {
        if (!this.passwordChangeHash)
            throw { code: "password_reset_used", text: "Password change link already used" };
        return this.getHash(token, this.passwordChangeSalt).then(function (hash) {
            if (this.passwordChangeHash != hash)
                throw { code: "invalid_password_change_link", text: "Incorrect password change link" };
            if (this.passwordChangeExpires.getTime() < (new Date()).getTime())
                throw { code: "password_change_link_expired", text: "Password change link expired" };
            return this.establishPassword(newPassword);
        }.bind(this));
    };
    /**
     * Verify a password on login (don't reveal password vs. user name is bad)
     *
     * @param password
     * @returns {*}
     */
    AuthenticatedPrincipal.prototype.authenticate = function (password, loggedIn, novalidate) {
        if (!novalidate && this.validateEmailCode && validateEmailForce.call(this))
            throw { code: "registration_unverified",
                text: "Please click on the link in your verification email to activate this account" };
        if (this.lockedOut)
            throw { code: "locked out", text: "Please contact your security administrator" };
        if (this.passwordExpires && (new Date()).getTime() > this.passwordExpires.getTime())
            throw { code: "loginexpired", text: "Your password has expired" };
        return this.getHash(password, this.passwordSalt).then(function (hash) {
            if (this.passwordHash !== hash) {
                return this.badLogin().then(function () {
                    this.persistSave();
                    throw loggedIn ?
                        { code: "invalid_password", text: "Incorrect password" } :
                        { code: "invalid_email_or_password", text: "Incorrect email or password" };
                }.bind(this));
            }
            else {
            }
            return Q(true);
        }.bind(this));
    };
    AuthenticatedPrincipal.prototype.badLogin = function () {
        if (maxLoginAttempts.call(this)) {
            this.unsuccesfulLogins.push(new Date());
            this.unsuccesfulLogins = _.filter(this.unsuccesfulLogins, function (attempt) {
                return ((new Date(attempt)).getTime() > ((new Date()).getTime() - 1000 * 60 * maxLoginPeriodMinutes.call(this)));
            });
            if (this.unsuccesfulLogins.length > maxLoginAttempts.call(this)) {
                if (this.role != defaultAdminRole.call(this)) {
                    this.lockedOut = true;
                }
                return Q.delay(10000);
            }
            return Q.delay(1000);
        }
        else
            return Q.delay(2000);
    };
    return AuthenticatedPrincipal;
}(amorphic_1.Remoteable(amorphic_1.Persistable(amorphic_1.Supertype))));
__decorate([
    amorphic_1.property({ toServer: false }),
    __metadata("design:type", String)
], AuthenticatedPrincipal.prototype, "email", void 0);
__decorate([
    amorphic_1.property({ toServer: false }),
    __metadata("design:type", String)
], AuthenticatedPrincipal.prototype, "newEmail", void 0);
__decorate([
    amorphic_1.property({ toServer: false }),
    __metadata("design:type", String)
], AuthenticatedPrincipal.prototype, "firstName", void 0);
__decorate([
    amorphic_1.property({ toServer: false }),
    __metadata("design:type", String)
], AuthenticatedPrincipal.prototype, "lastName", void 0);
__decorate([
    amorphic_1.property({ toServer: false }),
    __metadata("design:type", Boolean)
], AuthenticatedPrincipal.prototype, "emailValidated", void 0);
__decorate([
    amorphic_1.property({ toServer: false }),
    __metadata("design:type", Boolean)
], AuthenticatedPrincipal.prototype, "suspended", void 0);
__decorate([
    amorphic_1.property({ toServer: false }),
    __metadata("design:type", Boolean)
], AuthenticatedPrincipal.prototype, "lockedOut", void 0);
__decorate([
    amorphic_1.property({ toServer: false, toClient: false, type: Date }),
    __metadata("design:type", Array)
], AuthenticatedPrincipal.prototype, "unsuccesfulLogins", void 0);
__decorate([
    amorphic_1.property({ toServer: false }),
    __metadata("design:type", Date)
], AuthenticatedPrincipal.prototype, "passwordExpires", void 0);
__decorate([
    amorphic_1.property({ toServer: false }),
    __metadata("design:type", Boolean)
], AuthenticatedPrincipal.prototype, "mustChangePassword", void 0);
__decorate([
    amorphic_1.property({ toServer: false, toClient: false, type: String }),
    __metadata("design:type", Array)
], AuthenticatedPrincipal.prototype, "previousSalts", void 0);
__decorate([
    amorphic_1.property({ toServer: false, toClient: false, type: String }),
    __metadata("design:type", Array)
], AuthenticatedPrincipal.prototype, "previousHashes", void 0);
__decorate([
    amorphic_1.property({ toServer: false, values: {
            user: 'User',
            defaultAdminRole: 'Administrator' // An administrative user})
        } }),
    __metadata("design:type", String)
], AuthenticatedPrincipal.prototype, "role", void 0);
__decorate([
    amorphic_1.property({ toServer: false, persist: false }),
    __metadata("design:type", SecurityContext)
], AuthenticatedPrincipal.prototype, "securityContext", void 0);
__decorate([
    amorphic_1.property({ toClient: false, toServer: false }),
    __metadata("design:type", String)
], AuthenticatedPrincipal.prototype, "passwordHash", void 0);
__decorate([
    amorphic_1.property({ toClient: false, toServer: false }),
    __metadata("design:type", String)
], AuthenticatedPrincipal.prototype, "passwordSalt", void 0);
__decorate([
    amorphic_1.property({ toClient: false, toServer: false }),
    __metadata("design:type", String)
], AuthenticatedPrincipal.prototype, "passwordChangeHash", void 0);
__decorate([
    amorphic_1.property({ toClient: false, toServer: false }),
    __metadata("design:type", String)
], AuthenticatedPrincipal.prototype, "passwordChangeSalt", void 0);
__decorate([
    amorphic_1.property({ toClient: false, toServer: false }),
    __metadata("design:type", Date)
], AuthenticatedPrincipal.prototype, "passwordChangeExpires", void 0);
__decorate([
    amorphic_1.property({ toClient: false, toServer: false }),
    __metadata("design:type", String)
], AuthenticatedPrincipal.prototype, "validateEmailCode", void 0);
__decorate([
    amorphic_1.remote(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", void 0)
], AuthenticatedPrincipal.prototype, "roleSet", null);
__decorate([
    amorphic_1.remote(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", void 0)
], AuthenticatedPrincipal.prototype, "suspendUser", null);
__decorate([
    amorphic_1.remote(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", void 0)
], AuthenticatedPrincipal.prototype, "changeEmail", null);
__decorate([
    amorphic_1.remote(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", void 0)
], AuthenticatedPrincipal.prototype, "setRoleForUser", null);
AuthenticatedPrincipal = AuthenticatedPrincipal_1 = __decorate([
    amorphic_1.supertypeClass
], AuthenticatedPrincipal);
exports.AuthenticatedPrincipal = AuthenticatedPrincipal;
var AuthenticatingController = (function (_super) {
    __extends(AuthenticatingController, _super);
    function AuthenticatingController() {
        var _this = _super !== null && _super.apply(this, arguments) || this;
        _this.firstName = '';
        _this.lastName = '';
        _this.email = '';
        _this.newEmail = '';
        // Secure variables never leaked to the client
        _this.password = '';
        _this.confirmPassword = '';
        _this.newPassword = '';
        _this.passwordChangeHash = '';
        _this.verifyEmailCode = '';
        _this.loggedIn = false;
        return _this;
    }
    AuthenticatingController.prototype.isAdmin = function () {
        return this.securityContext.isAdmin();
    };
    AuthenticatingController.prototype.isLoggedIn = function () {
        return !!this.loggedIn;
    };
    AuthenticatingController.prototype.createAdmin = function () {
        AuthenticatedPrincipal.countFromPersistWithQuery({ role: defaultAdminRole.call(this) }).then(function (count) {
            if (count == 0) {
                var admin = new AuthenticatedPrincipal();
                admin.email = defaultEmail.call(this) || "amorphic@amorphic.com";
                admin.firstName = "Admin";
                admin.lastName = "User";
                admin.role = defaultAdminRole.call(this);
                this.amorphicate(admin);
                return admin.establishPassword(defaultPassword.call(this) || "admin", null, true, true);
            }
            else
                return Q(false);
        }.bind(this));
    };
    /**
     * Create a new principal if one does not exist. This method is used by the currently logged in user to create
     * new users. The principal info comes from the an object which should have the following properties:
     *
     * firstName, lastName, email, newPassword, confirmPassword, role
     *
     * Also used to reset a password
     */
    AuthenticatingController.prototype.createNewAdmin = function (adminUser, url, pageConfirmation, pageInstructions, reset) {
        // Check for security context of security admin
        if (this.loggedInRole !== defaultRole.call(this)) {
            throw { code: 'cannotcreateadmin', text: "Only a security admin can create users" };
        }
        if (adminUser.newPassword != adminUser.confirmPassword)
            throw { code: 'passwordmismatch', text: "Password's are not the same" };
        var principal;
        url = url ? urlparser.parse(url, true) : "";
        return AuthenticatedPrincipal.getFromPersistWithQuery({ email: adminUser.email }).then(function (principals) {
            if (reset) {
                if (principals.length == 0)
                    throw { code: "email_notfound", text: "Can't find this user" };
                principal = principals[0];
            }
            else {
                if (principals.length > 0)
                    throw { code: "email_registered", text: "This email is already registered" };
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
            return principal.establishPassword(adminUser.newPassword, principal.role == defaultAdminRole.call(this) ? null :
                new Date((new Date()).getTime() + temporaryPasswordExpiresMinutes.call(this) * 1000 * 60), false, true);
        }.bind(this)).then(function () {
            if (validateEmail.call(this))
                return principal.setEmailVerificationCode();
            else {
                return Q();
            }
        }.bind(this)).then(function () {
            if (url)
                this.sendEmail(validateEmail.call(this) ? "register_verify" : "register", principal.email, this.firstName + " " + this.lastName, [
                    { name: "firstName", content: this.firstName },
                    { name: "email", content: this.email },
                    { name: "link", content: url.protocol + "//" + url.host.replace(/:.*/, '') +
                            (url.port > 1000 ? ':' + url.port : '') +
                            "?email=" + encodeURIComponent(this.email) +
                            "&code=" + principal.validateEmailCode + "#verify_email" }
                ]);
            if (validateEmail.call(this) && pageInstructions)
                return this.setPage(pageInstructions);
            if (!validateEmail.call(this) && pageConfirmation)
                return this.setPage(pageConfirmation);
            return Q(principal);
        }.bind(this));
    };
    /**
     * Create a new principal if one does not exist and consider ourselves logged in
     *
     * @param password
     */
    AuthenticatingController.prototype.publicRegister = function (url, pageConfirmation, pageInstructions) {
        if (this.newPassword != this.confirmPassword)
            throw { code: 'passwordmismatch', text: "Password's are not the same" };
        var principal;
        url = urlparser.parse(url, true);
        return AuthenticatedPrincipal.countFromPersistWithQuery(queryFilter.call(this, { email: { $regex: new RegExp("^" + this.email.toLowerCase().replace(/([^0-9a-zA-Z])/g, "\\$1") + '$'), $options: 'i' } })).then(function (count) {
            if (count > 0)
                throw { code: "email_registered", text: "This email already registered" };
            this.setPrincipal(this.getPrincipal() || new AuthenticatedPrincipal());
            principal = this.getPrincipal();
            this.amorphicate(principal);
            principal.email = this.email;
            principal.firstName = this.firstName;
            principal.lastName = this.lastName;
            insertFilter.call(this, principal);
            return principal.establishPassword(this.newPassword);
        }.bind(this)).then(function () {
            if (validateEmail.call(this))
                return principal.setEmailVerificationCode();
            else
                return Q(true);
        }.bind(this)).then(function () {
            if (!validateEmail.call(this) || validateEmailAndLogin.call(this))
                this.setLoggedInState(principal);
            this.sendEmail(validateEmail.call(this) ? "register_verify" : "register", principal.email, principal.firstName + " " + principal.lastName, [
                { name: "firstName", content: this.firstName },
                { name: "email", content: this.email },
                { name: "link", content: url.protocol + "//" + url.host.replace(/:.*/, '') +
                        (url.port > 1000 ? ':' + url.port : '') +
                        "?email=" + encodeURIComponent(this.email) +
                        "&code=" + principal.validateEmailCode + "#verify_email" },
                { name: "verificationCode", content: this.getPrincipal().validateEmailCode }
            ]);
            if (validateEmail.call(this) && pageInstructions)
                return this.setPage(pageInstructions);
            if (!validateEmail.call(this) && pageConfirmation)
                return this.setPage(pageConfirmation);
        }.bind(this));
    };
    /**
     * login the user
     */
    AuthenticatingController.prototype.publicLoginBind = function (page, forceChange) {
        var principal;
        if (this.loggedIn)
            throw { code: "already_loggedin", text: "Already logged in" };
        var query = AuthenticatedPrincipal.getFromPersistWithQuery(queryFilter.call(this, { email: { $regex: new RegExp("^" + this.email.toLowerCase().replace(/([^0-9a-zA-Z])/g, "\\$1") + '$'), $options: 'i' } }), null, null, null, true);
        return query.then(function (principals) {
            if (principals.length == 0 || principals[0].suspended) {
                log.call(this, "Log In attempt for " + this.email + " failed (invalid email)");
                throw { code: "invalid_email_or_password",
                    text: "Incorrect email or password" };
            }
            principal = principals[0];
            this.amorphicate(principal);
            return principal.authenticate(this.password);
        }.bind(this)).then(function () {
            return AuthenticatedPrincipal.getFromPersistWithId(principal._id);
        }.bind(this)).then(function (p) {
            principal = p;
            this.amorphicate(principal);
            forceChange = forceChange || principal.mustChangePassword;
            if (forceChange && !this.newPassword)
                throw { code: "changePassword", text: "Please change your password" };
            return forceChange ? this.changePasswordForPrincipal(principal) : Q(true);
        }.bind(this)).then(function (status) {
            if (status)
                this.setLoggedInState(principal);
            return page ? this.setPage(page) : Q(true);
        }.bind(this));
    };
    /**
     * login the user
     */
    AuthenticatingController.prototype.publicLoginFatArrow = function (page, forceChange) {
        var _this = this;
        var principal;
        if (this.loggedIn)
            throw { code: "already_loggedin", text: "Already logged in" };
        var query = AuthenticatedPrincipal.getFromPersistWithQuery(queryFilter.call(this, { email: { $regex: new RegExp("^" + this.email.toLowerCase().replace(/([^0-9a-zA-Z])/g, "\\$1") + '$'), $options: 'i' } }), null, null, null, true);
        return query.then(function (principals) {
            if (principals.length == 0 || principals[0].suspended) {
                log.call(_this, "Log In attempt for " + _this.email + " failed (invalid email)");
                throw { code: "invalid_email_or_password",
                    text: "Incorrect email or password" };
            }
            principal = principals[0];
            _this.amorphicate(principal);
            return principal.authenticate(_this.password);
        }).then(function () {
            return AuthenticatedPrincipal.getFromPersistWithId(principal._id);
        }).then(function (p) {
            principal = p;
            _this.amorphicate(principal);
            forceChange = forceChange || principal.mustChangePassword;
            if (forceChange && !_this.newPassword)
                throw { code: "changePassword", text: "Please change your password" };
            return forceChange ? _this.changePasswordForPrincipal(principal) : true;
        }).then(function (status) {
            if (status)
                _this.setLoggedInState(principal);
            return page ? _this.setPage(page) : Q(true);
        });
    };
    /**
     * login the user
     */
    AuthenticatingController.prototype.publicLogin = function (page, forceChange) {
        return __awaiter(this, void 0, void 0, function () {
            var query, principals, principal, principal, status, _a;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0:
                        if (this.loggedIn)
                            throw { code: "already_loggedin", text: "Already logged in" };
                        query = AuthenticatedPrincipal.getFromPersistWithQuery(queryFilter.call(this, { email: { $regex: new RegExp("^" + this.email.toLowerCase().replace(/([^0-9a-zA-Z])/g, "\\$1") + '$'),
                                $options: 'i' } }), null, null, null, true);
                        return [4 /*yield*/, query];
                    case 1:
                        principals = _b.sent();
                        if (principals.length == 0 || principals[0].suspended) {
                            log.call(this, "Log In attempt for " + this.email + " failed (invalid email)");
                            throw { code: "invalid_email_or_password",
                                text: "Incorrect email or password" };
                        }
                        principal = principals[0];
                        this.amorphicate(principal);
                        return [4 /*yield*/, principal.authenticate(this.password)];
                    case 2:
                        _b.sent();
                        return [4 /*yield*/, AuthenticatedPrincipal.getFromPersistWithId(principal._id)];
                    case 3:
                        principal = _b.sent();
                        this.amorphicate(principal);
                        forceChange = forceChange || principal.mustChangePassword;
                        if (forceChange && !this.newPassword)
                            throw { code: "changePassword", text: "Please change your password" };
                        if (!forceChange) return [3 /*break*/, 5];
                        return [4 /*yield*/, this.changePasswordForPrincipal(principal)];
                    case 4:
                        _a = _b.sent();
                        return [3 /*break*/, 6];
                    case 5:
                        _a = true;
                        _b.label = 6;
                    case 6:
                        status = _a;
                        if (status)
                            this.setLoggedInState(principal);
                        if (!page) return [3 /*break*/, 8];
                        return [4 /*yield*/, this.setPage(page)];
                    case 7:
                        _b.sent();
                        _b.label = 8;
                    case 8: return [2 /*return*/];
                }
            });
        });
    };
    /**
     * login the user with changed email. Also verify email code
     */
    AuthenticatingController.prototype.publicLoginWithNewEmail = function (page) {
        var principal;
        return AuthenticatedPrincipal.getFromPersistWithQuery(queryFilter.call(this, { newEmail: { $regex: new RegExp("^" + this.email.toLowerCase().replace(/([^0-9a-zA-Z])/g, "\\$1") + '$', "i") } }), null, null, null, true).then(function (principals) {
            if (principals.length == 0) {
                log.call(this, "Log In attempt for " + this.email + " failed (invalid email)");
                throw { code: "invalid_email_or_password",
                    text: "Incorrect email or password" };
            }
            principal = principals[0];
            this.amorphicate(principal);
            return principal.authenticate(this.password);
        }.bind(this)).then(function () {
            return AuthenticatedPrincipal.getFromPersistWithId(principal._id);
        }.bind(this)).then(function (p) {
            principal = p;
            this.amorphicate(principal);
            if (principal.mustChangePassword && !this.newPassword)
                throw { code: "changePassword", text: "Please change your password" };
            return principal.mustChangePassword ? this.changePasswordForPrincipal(principal) : Q(true);
        }.bind(this)).then(function (status) {
            return principal.consumeEmailVerificationCode(this.verifyEmailCode);
        }.bind(this)).then(function () {
            this.setLoggedInState(principal);
            principal.email = this.email;
            principal.newEmail = ""; // No need to track the changed email anymore
            principal.persistSave();
            // Send an email changed confirmation email
            this.sendEmail("confirm_emailchange", this.email, principal.email, principal.firstName + " " + principal.lastName, [
                { name: "email", content: this.email },
                { name: "firstName", content: principal.firstName }
            ]);
            return page ? this.setPage(page) : Q(true);
        }.bind(this));
    };
    /**
     *  Set up all fields to indicate logged in
     */
    AuthenticatingController.prototype.setLoggedInState = function (principal) {
        this.loggedIn = true;
        this.loggedInRole = principal.role;
        this.setPrincipal(principal);
        // One way so you can't spoof from client
        this.securityContext = new SecurityContext(principal, principal.role);
    };
    /**
     *  Set up all fields to indicate logged out
     */
    AuthenticatingController.prototype.setLoggedOutState = function () {
        this.setPrincipal(null);
        this.loggedIn = false;
        this.loggedInRole = null;
        this.securityContext = null;
    };
    /*
     * logout the current user
     */
    AuthenticatingController.prototype.publicLogout = function (page) {
        log.call(this, "Customer " + this.email + " logged out");
        this.setLoggedOutState();
        return page ? this.setPage(page) : null;
    };
    AuthenticatingController.prototype.setPage = function (page) {
        // should be overriddent if you want to go to a page
    };
    /**
     * change an email address for a logged in user
     */
    AuthenticatingController.prototype.changeEmail = function (page, url) {
        return __awaiter(this, void 0, void 0, function () {
            var principal, oldEmail, newEmail;
            return __generator(this, function (_a) {
                url = urlparser.parse(url, true);
                principal = this.getPrincipal();
                oldEmail = principal.email;
                newEmail = this.newEmail;
                return [2 /*return*/, Q(true).then(function () {
                        return principal.authenticate(this.password, null, true);
                    }.bind(this)).then(function () {
                        return AuthenticatedPrincipal.countFromPersistWithQuery(queryFilter.call(this, { email: newEmail }));
                    }.bind(this)).then(function (count) {
                        if (count > 0)
                            throw { code: "email_registered", text: "This email already registered" };
                    }.bind(this)).then(function () {
                        if (validateEmail.call(this))
                            return principal.setEmailVerificationCode();
                        else {
                            return Q(false);
                        }
                    }.bind(this)).then(function () {
                        if (!deferEmailChange.call(this))
                            this.email = newEmail;
                        principal.newEmail = newEmail;
                        principal.persistSave();
                        // Send an email to old email address which is purely informational
                        this.sendEmail("email_changed", oldEmail, principal.email, principal.firstName + " " + principal.lastName, [
                            { name: "oldEmail", content: oldEmail },
                            { name: "email", content: newEmail },
                            { name: "firstName", content: principal.firstName }
                        ]);
                        // Send an email to new email address asking to verify the new email
                        // address
                        this.sendEmail(validateEmail.call(this) ? "email_changed_verify" : "email_changed", newEmail, principal.firstName + " " + principal.lastName, [
                            { name: "oldEmail", content: oldEmail },
                            { name: "email", content: newEmail },
                            { name: "firstName", content: principal.firstName },
                            { name: "link", content: url.protocol + "//" + url.host.replace(/:.*/, '') +
                                    (url.port > 1000 ? ':' + url.port : '') +
                                    "?email=" + encodeURIComponent(newEmail) +
                                    "&code=" + principal.validateEmailCode + (deferEmailChange.call(this) ? "#verify_email_change" : "#verify_email") },
                            { name: "verificationCode", content: principal.validateEmailCode }
                        ]);
                        log.call(this, "Changed email " + oldEmail + " to " + newEmail);
                        return page ? this.setPage(page) : Q(true);
                    }.bind(this))];
            });
        });
    };
    AuthenticatingController.prototype.resendChangeEmailValidationCode = function (url) {
        url = urlparser.parse(url, true);
        var principal = this.getPrincipal();
        this.sendEmail("email_verify", principal.email, principal.firstName + " " + principal.lastName, [
            { name: "email", content: principal.email },
            { name: "firstName", content: principal.firstName },
            { name: "link", content: url.protocol + "//" + url.host.replace(/:.*/, '') +
                    (url.port > 1000 ? ':' + url.port : '') +
                    "?email=" + encodeURIComponent(principal.email) +
                    "&code=" + principal.validateEmailCode + "#verify_email" },
            { name: "verificationCode", content: principal.validateEmailCode }
        ]);
        log.call(this, "Resent email validation code to " + principal.email);
    };
    /**
     * Change the password for a logged in user verifying old password
     * Also called from login on a force change password so technically you don't have to be logged in
     */
    AuthenticatingController.prototype.changePassword = function (page) {
        if (!this.loggedIn)
            throw { code: "not_loggedin", text: "Not logged in" };
        return this.changePasswordForPrincipal(this.getPrincipal(), page);
    };
    AuthenticatingController.prototype.changePasswordForPrincipal = function (principal, page) {
        return principal.authenticate(this.password, true).then(function () {
            return principal.establishPassword(this.newPassword, passwordExpiresMinutes.call(this) ?
                new Date((new Date()).getTime() + passwordExpiresMinutes.call(this) * 1000 * 60) : null).then(function () {
                log.call(this, "Changed password for " + principal.email);
                if (this.sendEmail)
                    this.sendEmail("password_changed", principal.email, principal.firstName, [
                        { name: "firstName", content: principal.firstName }
                    ]);
                return page ? this.setPage(page) : Q(true);
            }.bind(this));
        }.bind(this));
    };
    /**
     * Request that an email be sent with a password change link
     */
    AuthenticatingController.prototype.publicResetPassword = function (url, page) {
        url = urlparser.parse(url, true);
        log.call(this, "Request password reset for " + this.email);
        return AuthenticatedPrincipal.getFromPersistWithQuery(queryFilter.call(this, { email: this.email }), null, null, null, true).then(function (principals) {
            if (principals.length < 1)
                throw { code: "invalid_email", text: "Incorrect email" };
            var principal = principals[0];
            this.amorphicate(principal);
            return principal.setPasswordChangeHash().then(function (token) {
                this.sendEmail("password_reset", this.email, principal.firstName, [
                    { name: "link", content: url.protocol + "//" + url.host.replace(/:.*/, '') +
                            (url.port > 1000 ? ':' + url.port : '') +
                            "?email=" + encodeURIComponent(this.email) +
                            "&token=" + token + "#reset_password_from_code" },
                    { name: "firstName", content: principal.firstName }
                ]);
                return page ? this.setPage(page) : Q(true);
            }.bind(this));
        }.bind(this));
    };
    /**
     * Change the password given the token and log the user in
     * Token was generated in publicResetPassword and kept in principal entity to verify
     */
    AuthenticatingController.prototype.publicChangePasswordFromToken = function (page) {
        var principal;
        return AuthenticatedPrincipal.getFromPersistWithQuery(queryFilter.call(this, { email: this.email }), null, null, null, true).then(function (principals) {
            if (principals.length < 1)
                throw { code: "ivalid_password_change_token",
                    text: "Invalid password change link - make sure you copied correctly from the email" };
            principal = principals[0];
            this.amorphicate(principal);
            return principal.consumePasswordChangeToken(this.passwordChangeHash, this.newPassword);
        }.bind(this)).then(function () {
            return AuthenticatedPrincipal.getFromPersistWithId(principal._id);
        }.bind(this)).then(function (p) {
            principal = p;
            this.amorphicate(principal);
            return principal.establishPassword(this.newPassword);
        }.bind(this)).then(function () {
            this.setLoggedInState(principal);
            log.call(this, "Changed password for " + principal.email);
            if (this.sendEmail) {
                this.sendEmail("password_changed", principal.email, principal.firstName, [
                    { name: "firstName", content: principal.firstName }
                ]);
            }
            return page ? this.setPage(page) : Q(true);
        }.bind(this));
    };
    /**
     * Verify the email code
     */
    AuthenticatingController.prototype.publicVerifyEmailFromCode = function (page) {
        var principal;
        return AuthenticatedPrincipal.getFromPersistWithQuery(queryFilter.call(this, { email: this.email }), null, null, null, true).then(function (principals) {
            if (principals.length < 1)
                throw { code: "invalid_email_verification_code",
                    text: "Invalid verification link - make sure you copied correctly from the email" };
            principal = principals[0];
            this.amorphicate(principal);
            return principal.consumeEmailVerificationCode(this.verifyEmailCode);
        }.bind(this)).then(function () {
            return page ? this.setPage(page) : Q(true);
        }.bind(this));
    };
    /**
     * Verify the email code assuming principal already in controller
     */
    AuthenticatingController.prototype.privateVerifyEmailFromCode = function (verifyEmailCode) {
        var principal = this.getPrincipal();
        try {
            return principal.consumeEmailVerificationCode(verifyEmailCode);
        }
        catch (e) {
            return Q(false);
        }
    };
    return AuthenticatingController;
}(amorphic_1.Bindable(amorphic_1.Remoteable(amorphic_1.Persistable(amorphic_1.Supertype)))));
__decorate([
    amorphic_1.property({ length: 50, rule: ["name", "required"] }),
    __metadata("design:type", String)
], AuthenticatingController.prototype, "firstName", void 0);
__decorate([
    amorphic_1.property({ length: 50, rule: ["name", "required"] }),
    __metadata("design:type", String)
], AuthenticatingController.prototype, "lastName", void 0);
__decorate([
    amorphic_1.property({ length: 50, rule: ["text", "email", "required"] }),
    __metadata("design:type", String)
], AuthenticatingController.prototype, "email", void 0);
__decorate([
    amorphic_1.property({ length: 50, rule: ["text", "email", "required"] }),
    __metadata("design:type", String)
], AuthenticatingController.prototype, "newEmail", void 0);
__decorate([
    amorphic_1.property({ toClient: false }),
    __metadata("design:type", String)
], AuthenticatingController.prototype, "password", void 0);
__decorate([
    amorphic_1.property({ toClient: false, rule: ["required"] }),
    __metadata("design:type", String)
], AuthenticatingController.prototype, "confirmPassword", void 0);
__decorate([
    amorphic_1.property({ toClient: false, rule: ["required"] }),
    __metadata("design:type", String)
], AuthenticatingController.prototype, "newPassword", void 0);
__decorate([
    amorphic_1.property({ toClient: false }),
    __metadata("design:type", String)
], AuthenticatingController.prototype, "passwordChangeHash", void 0);
__decorate([
    amorphic_1.property({ toClient: false }),
    __metadata("design:type", String)
], AuthenticatingController.prototype, "verifyEmailCode", void 0);
__decorate([
    amorphic_1.property({ toServer: false }),
    __metadata("design:type", Boolean)
], AuthenticatingController.prototype, "loggedIn", void 0);
__decorate([
    amorphic_1.property({ toServer: false }),
    __metadata("design:type", String)
], AuthenticatingController.prototype, "loggedInRole", void 0);
__decorate([
    amorphic_1.property({ toServer: false }),
    __metadata("design:type", SecurityContext)
], AuthenticatingController.prototype, "securityContext", void 0);
__decorate([
    amorphic_1.remote({ validate: function () { return this.validate(document.getElementById('publicRegisterFields')); } }),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object, Object, Object, Object]),
    __metadata("design:returntype", void 0)
], AuthenticatingController.prototype, "createNewAdmin", null);
__decorate([
    amorphic_1.remote({ validate: function () {
            return this.validate(document.getElementById('publicRegisterFields'));
        } }),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object, Object]),
    __metadata("design:returntype", void 0)
], AuthenticatingController.prototype, "publicRegister", null);
__decorate([
    amorphic_1.remote({ validate: function () { return this.validate(document.getElementById('publicLoginFields')); } }),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", void 0)
], AuthenticatingController.prototype, "publicLoginBind", null);
__decorate([
    amorphic_1.remote({ validate: function () { return this.validate(document.getElementById('publicLoginFields')); } }),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", void 0)
], AuthenticatingController.prototype, "publicLoginFatArrow", null);
__decorate([
    amorphic_1.remote({ validate: function () { return this.validate(document.getElementById('publicLoginFields')); } }),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", Promise)
], AuthenticatingController.prototype, "publicLogin", null);
__decorate([
    amorphic_1.remote({ validate: function () { return this.validate(document.getElementById('publicLoginFields')); } }),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", void 0)
], AuthenticatingController.prototype, "publicLoginWithNewEmail", null);
__decorate([
    amorphic_1.remote(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", void 0)
], AuthenticatingController.prototype, "publicLogout", null);
__decorate([
    amorphic_1.remote({ on: 'client' }),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", void 0)
], AuthenticatingController.prototype, "setPage", null);
__decorate([
    amorphic_1.remote({ validate: function () { return this.validate(document.getElementById('changeEmailFields')); } }),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", Promise)
], AuthenticatingController.prototype, "changeEmail", null);
__decorate([
    amorphic_1.remote({ validate: function () { return this.validate(document.getElementById('changeEmailFields')); } }),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", void 0)
], AuthenticatingController.prototype, "resendChangeEmailValidationCode", null);
__decorate([
    amorphic_1.remote({ validate: function () { return this.validate(document.getElementById('changePasswordFields')); } }),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", void 0)
], AuthenticatingController.prototype, "changePassword", null);
__decorate([
    amorphic_1.remote({ validate: function () { return this.validate(document.getElementById('publicResetPasswordFields')); } }),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", void 0)
], AuthenticatingController.prototype, "publicResetPassword", null);
__decorate([
    amorphic_1.remote({ validate: function () { return this.validate(document.getElementById('publicChangePasswordFromTokenFields')); } }),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", void 0)
], AuthenticatingController.prototype, "publicChangePasswordFromToken", null);
__decorate([
    amorphic_1.remote(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", void 0)
], AuthenticatingController.prototype, "publicVerifyEmailFromCode", null);
__decorate([
    amorphic_1.remote(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", void 0)
], AuthenticatingController.prototype, "privateVerifyEmailFromCode", null);
AuthenticatingController = __decorate([
    amorphic_1.supertypeClass
], AuthenticatingController);
exports.AuthenticatingController = AuthenticatingController;
var AuthenticatedPrincipal_1;
//# sourceMappingURL=index.js.map