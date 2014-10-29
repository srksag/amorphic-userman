# amorphic-userman
## Purpose
An amorphic module for identity management.  Key functions include:
* Registering user and admin accounts
* Verify an email address as part of registration
* Mixing in all of the properties (e.g. email, password, salts) in a principal entity of your choice
* Change password
* Change email
* Lost password
## Installation
Install on node via  npm:

    npm install amorphic-userman

## Example
In the config.json file you add a modules section like this:

    {
         "modules":      {
            "userman":  {
                "require": "amorphic-userman",
                "controller": {"require": "controller", "template": "Controller"},
                "principal": {"require" : "person", "template": "Person"},
                "validateEmail": true
            },
        }
    }

The properties are:

* require - the name of the module in node_modules (amorphi-userman)
* controller has two properties, require, which is the require path for the controller class and
template which is the template for the controller
* principal has two properties, require, which is the require path for a a principal class and
template which is the thempalte for the principal

userman will add these properties to the principal template and manage them for you

        passwordHash:           {toClient: false, toServer: false, type: String},
        passwordSalt:           {toClient: false, toServer: false, type: String },

        passwordChangeHash:     {toClient: false, toServer: false, type: String, value: ""},
        passwordChangeSalt:     {toClient: false, toServer: false, type: String, value: ""},
        passwordChangeExpires:  {toClient: false, toServer: false, type: Date},

        validateEmailCode:      {toClient: false, toServer: false, type: String}, // If present status is pending

        role:                   {toServer: false, type: String, init: "user", values: {
            "user": "User",             // A normal user
            "admin": "Administrator"}   // An administrative user
        },
        roleSet:  {on: "server", body: function (role) {
            if (this.getSecurityContext.role == 'admin' && (role == 'admin' || role == 'user'))
                this.role = role;
            else
                throw {code: "role_change", text: "You cannot change roles"};
        }},
        isAdmin: function () {
            return this.role == 'admin';
        },
You are expected to have these fields in the principal template:

        firstName:              {type: String},
        lastName:               {type: String},
        email:                  {type: String},

You don't need to worry about the password fields as they are setup when you register or change passwords.  You
can test the role or call isAdmin to determin if the user is an admin user.

userman will add these properties to your controller and manage them for you

        firstName:              {type: String, value: "", length: 50, rule: ["name", "required"]},
        lastName:               {type: String, value: "", length: 50, rule: ["name", "required"]},
        email:                  {type: String, value: "", length: 50, rule: ["text", "email", "required"]},
        newEmail:               {type: String, value: "", length: 50, rule: ["text", "email", "required"]},
        principal:              {toServer: false, type: Principal},

        // Secure variables never leaked to the client

        password:               {toClient: false, type: String, value: ""},
        confirmPassword:        {toClient: false, type: String, value: "", rule:["required"], validate: function () {
                                    if (this.value && this.newPassword && this.newPassword != this.value)
                                        throw {code: 'passwordmismatch', text:"Password's are not the same"};
                                }},
        newPassword:            {toClient: false, type: String, value: "", rule:["required"], validate: function () {
                                    if (this.confirmPassword && this.value && this.value != this.confirmPassword)
                                        throw {code: 'passwordmismatch', text: "Password's are not the same"};
                                }},

        passwordChangeHash:     {toClient: false, type: String},
        verifyEmailCode:        {toClient: false, type: String},

        // Secure variables never accepted from the client

        securityContext:        {toServer: false,type: SecurityContext},
        loggedIn:               {toServer: false, type: Boolean, value: false},
        loggedInRole:           {toServer: false, type: String},

the controller must also have a property to represent the principal.  You can configure this property in the json.config for the module using the fields property of the controller property
 
        "controller": {"require": "controller", "template": "Controller", fields: "loggedInPerson"},
   
By default the property is named principal.  If the property is not already defined in controller it will be added

These fields are for your view to bind with when interacting with userman.  You will seem them referenced in the
default views in the pages sub-directory.  You can use the default views for login, changing passwords, registration
 or create your own.
 
 userman provides these methods in the controller for you to manage users

* __createNewAdmin(newAdmin, url, pageConfirmation, pageInstructions)__ -
Creates a new principal if one does not exist. This method is intended create new users by the currently
logged in admin user.
The url of your application is passed as a parameter and used to construct a verification email link.
pageConfirmation and pageInstructions are two paths that will be passed in call to the setPage method
on your controller to route to either an instruction page for receiving the verification email or
a confirmation page to let the user know they were successfully registered.
Expects properties -  email, firstName, lastName, newPassword, confirmPassword and role - on a object hash (newAdmin)


* __publicRegister(url, pageConfirmation, pageInstructions)__ -
Creates a new principal if one does not exist and logs them in.
The url of your application is passed as a parameter and used to construct a verification email link.
pageConfirmation and pageInstructions are two paths that will be passed in call to the setPage method
on your controller to route to either an instruction page for receiving the verification email or 
a confirmation page to let the user know they were successfully registered.
Expects controller properties, email, firstName, lastName and newPassword.
  
  
* __publicLogin(page)__ -
Logs in a principal.  
A page can be passed in as a path that will be passed back in a call to
the setPage method to route the user to a page after login.
Expects controller properties, email and password.
  
  
* __publicLogout()__ -
Logs out the logged in principal. 
A page can be passed in as a path that will be passed back in a call to
the setPage method to route the user to a page after login.
  

* __changeEmail(page)__ - 
Changes the email after authenticating the principal. 
A page can be passed in as a path that will be passed back in a call to
the setPage method to route the user to a page after login.
Controller properties oldEmail, newEmail and password are expected.
An email is sent to the old and new email address.
  
  
* __changePassword(page)__ -
Changes the password after authenticating the principal. 
A page can be passed in as a path that will be passed back in a call to
the setPage method to route the user to a page when done.
Controller properties password and newPassword are expected.
    

* __publicResetPassword(url, page)__ -
Sends an email with a link that let's a principal reset their password.
The url of your application is passed as a parameter and used to construct the email link.
A page can be passed in as a path that will be passed back in a call to
the setPage method to route the user to a page when done.
  

* __publicChangePasswordFromToken(page)__ -
Resets the password given a token that was parsed from the email send by publicResetPassword.
A page can be passed in as a path that will be passed back in a call to
the setPage method to route the user to a page when done.
Controller properties passwordChangeHash is expected to contains the token= parameter from the url
and newPassword the new password to be set.
  
  
* __publicVerifyEmailFromCode(page)__ -
Verifies that a principal has a valid email address by verifying a token that was parsed from the email sent
by publicRegister.
A page can be passed in as a path that will be passed back in a call to
the setPage method to route the user to a page after login.
Controller properties verifyEmailCode is expected to contains the code= parameter from the url,
email is expected to be the email= parameter.

userman uses a method sendMail(templateName, emailAddress, firstName, insertions) to send emails.  The insertions
parameter is an array of objects that contain a name/parameter property pair to be substitued in the mails.  Using
the amorphic-mandril module these emails can be sent via mandrill.

## License

amorhic-userman is licensed under the MIT license



