/// <reference types="q" />
import * as Q from 'q';
import { Supertype } from 'amorphic';
export declare class SecurityContext extends Supertype {
    principal: AuthenticatedPrincipal;
    role: string;
    constructor(principal: any, role: any);
    isLoggedIn(): boolean;
    isAdmin(): boolean;
}
export declare class AuthenticatedPrincipal extends Supertype {
    email: string;
    newEmail: string;
    firstName: string;
    lastName: string;
    emailValidated: boolean;
    suspended: boolean;
    lockedOut: boolean;
    unsuccesfulLogins: Array<Date>;
    passwordExpires: Date;
    mustChangePassword: boolean;
    previousSalts: Array<string>;
    previousHashes: Array<String>;
    role: string;
    securityContext: SecurityContext;
    passwordHash: string;
    passwordSalt: string;
    passwordChangeHash: string;
    passwordChangeSalt: string;
    passwordChangeExpires: Date;
    validateEmailCode: string;
    roleSet(role: any): void;
    suspendUser(suspended: any): any;
    changeEmail(email: any): any;
    setRoleForUser(role: any): any;
    isAdmin(): boolean;
    /**
     * Create a password hash and save the object
     *
     * @param password
     * @returns {*} promise (true) when done
     * throws an exception if the password does not meet password rules
     */
    establishPassword(password: any, expires: any, noValidate: any, forceChange: any): Q.Promise<{}>;
    /**
     * Check password rules for a new password
     *
     * @param password
     * @return {*}
     */
    validateNewPassword(password: any): void;
    /**
     * Return a password hash
     *
     * @param password
     * @param salt
     * @return {*}
     */
    getHash(password: any, salt: any): Q.Promise<string>;
    /**
     * Get a secure random string for the salt
     *
     * @return {*}
     */
    getSalt(): Q.Promise<string>;
    setEmailVerificationCode(): any;
    consumeEmailVerificationCode(code: any): any;
    /**
     * Create a one-way hash for changing passwords
     * @returns {*}
     */
    setPasswordChangeHash(): Q.Promise<{}>;
    /**
     * Consume a password change token and change the password
     *
     * @param token
     * @returns {*}
     */
    consumePasswordChangeToken(token: any, newPassword: any): Q.Promise<{}>;
    /**
     * Verify a password on login (don't reveal password vs. user name is bad)
     *
     * @param password
     * @returns {*}
     */
    authenticate(password: any, loggedIn: any, novalidate: any): Q.Promise<{}>;
    badLogin(): Q.Promise<void>;
}
export declare abstract class AuthenticatingController extends Supertype {
    firstName: string;
    lastName: string;
    email: string;
    newEmail: string;
    password: string;
    confirmPassword: string;
    newPassword: string;
    passwordChangeHash: string;
    verifyEmailCode: string;
    loggedIn: boolean;
    loggedInRole: string;
    isAdmin(): boolean;
    securityContext: SecurityContext;
    abstract setPrincipal(principal: AuthenticatedPrincipal): any;
    abstract getPrincipal(): AuthenticatedPrincipal;
    isLoggedIn(): boolean;
    createAdmin(): void;
    /**
     * Create a new principal if one does not exist. This method is used by the currently logged in user to create
     * new users. The principal info comes from the an object which should have the following properties:
     *
     * firstName, lastName, email, newPassword, confirmPassword, role
     *
     * Also used to reset a password
     */
    createNewAdmin(adminUser: any, url: any, pageConfirmation?: any, pageInstructions?: any, reset?: any): any;
    /**
     * Create a new principal if one does not exist and consider ourselves logged in
     *
     * @param password
     */
    publicRegister(url: any, pageConfirmation?: any, pageInstructions?: any): any;
    /**
     * login the user
     */
    publicLogin(page?: any, forceChange?: any): any;
    /**
     * login the user with changed email. Also verify email code
     */
    publicLoginWithNewEmail(page?: any): any;
    /**
     *  Set up all fields to indicate logged in
     */
    setLoggedInState(principal: any): void;
    /**
     *  Set up all fields to indicate logged out
     */
    setLoggedOutState(): void;
    publicLogout(): void;
    /**
     * change an email address for a logged in user
     */
    changeEmail(page: any, url: any): Q.Promise<{}>;
    abstract sendEmail(slug: any, email: any, name: any, emails: Array<any>): any;
    resendChangeEmailValidationCode(url: any): void;
    /**
     * Change the password for a logged in user verifying old password
     * Also called from login on a force change password so technically you don't have to be logged in
     */
    changePassword(page: any): any;
    changePasswordForPrincipal(principal: any, page?: any): any;
    /**
     * Request that an email be sent with a password change link
     */
    publicResetPassword(url: any, page: any): any;
    /**
     * Change the password given the token and log the user in
     * Token was generated in publicResetPassword and kept in principal entity to verify
     */
    publicChangePasswordFromToken(page: any): any;
    /**
     * Verify the email code
     */
    publicVerifyEmailFromCode(page?: any): any;
    /**
     * Verify the email code assuming principal already in controller
     */
    privateVerifyEmailFromCode(verifyEmailCode: any): any;
}
