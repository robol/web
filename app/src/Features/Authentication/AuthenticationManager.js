const Settings = require('settings-sharelatex')
const { User } = require('../../models/User')
const { db, ObjectId } = require('../../infrastructure/mongodb')
const bcrypt = require('bcrypt')
const EmailHelper = require('../Helpers/EmailHelper')

const {
  InvalidEmailError,
  InvalidPasswordError,
} = require('./AuthenticationErrors')
const util = require('util')
const ldap = require('ldapjs')

const BCRYPT_ROUNDS = Settings.security.bcryptRounds || 12
const BCRYPT_MINOR_VERSION = Settings.security.bcryptMinorVersion || 'a'

const _checkWriteResult = function (result, callback) {
  // for MongoDB
  if (result && result.modifiedCount === 1) {
    callback(null, true)
  } else {
    callback(null, false)
  }
}

const AuthenticationManager = {
  authenticate(query, password, callback) {
    // Using Mongoose for legacy reasons here. The returned User instance
    // gets serialized into the session and there may be subtle differences
    // between the user returned by Mongoose vs mongodb (such as default values)
    User.findOne(query, (error, user) => {
      AuthenticationManager.authUserObj(error, user, query, password, callback);
    });
  },

  // The following methods, namely authUserObj, login, createIfNotExistAndLogin,
  // and ldapAuth, have been introduced to handle the LDAP authentication.
  //
  // At the moment they are specific for the configuration for the UniPi LDAP
  // server, although they might be made to work more generally for more
  // specific cases.

  authUserObj(error, user, query, password, callback) {
    //non ldap / local admin user
    const adminMail = process.env.ADMIN_MAIL;
    
    if (error) {
      return callback(error)
    }
    
    const pieces = query.email.split('@');
    const username = pieces[0];
    const domain = pieces[1];
    const ldap_domains = process.env.LDAP_DOMAINS === undefined ? [] : process.env.LDAP_DOMAINS.split(",");

    //check for local admin user
    if (user && user.hashedPassword) {
      // We authenticate emails that do not belong to LDAP domains using the
      // traditional Overleaf authentication.
      if (! ldap_domains.includes(domain)) {
        bcrypt.compare(password, user.hashedPassword, function (error, match) {
          if (error) {
            return callback(error)
          }
          if (!match) {
            return callback(null, null)
          }
          AuthenticationManager.login(user, password, callback)
        })
        return null
      }
    }
    
    //check if user is in ldap
    AuthenticationManager.ldapAuth(query, password,
      AuthenticationManager.createIfNotExistAndLogin, callback, adminMail, user)
  },

  //login with any passwd
  login(user, password, callback) {
    AuthenticationManager.checkRounds(
      user,
      user.hashedPassword,
      password,
      function (err) {
        if (err) {
          return callback(err)
        }
        callback(null, user)
      }
    )
  },

  createIfNotExistAndLogin(query, adminMail, user, cn, callback) {
    if (query.email != adminMail & (!user || !user.hashedPassword)) {
      //create random pass for local userdb, does not get checked for ldap users during login
      let pass = require("crypto").randomBytes(32).toString("hex")
      const userRegHand = require('../User/UserRegistrationHandler.js')
      
      let cn_pieces = cn.split(' ');
      let first_name = cn_pieces[0];
      let last_name = cn_pieces.slice(1).join(' ');
      
      userRegHand.registerNewUser({
        email: query.email,
        password: pass,
        first_name: first_name,
        last_name: last_name
      },
      function (error, user) {
        if (error) {
          callback(error)
        }

        const update = {
          admin: false,
          'emails.0.confirmedAt': Date.now()
        };

        console.log("user %s added to local library", query.email)
        User.findOneAndUpdate(query, update, (error, user) => {
          if (error) {
            return callback(error)
          }
          if (user && user.hashedPassword) {
            AuthenticationManager.login(user, "randomPass", callback)
          }
        })
      })
    } else {
      AuthenticationManager.login(user, "randomPass", callback)
    }
  },
  
  findUserDetails(client, username, domain, base, callback) {
      const opts = {
          scope: 'sub',
          attributes: [ 'cn', 'uid' ],
          filter: 'uid=' + username
      };
      
      var counter = 0;
  
      client.search(base, opts, function (err, res) {
          res.on('searchEntry', function (entry) {
              counter = counter + 1;
              if (counter == 1) {
                  let cn = entry.toObject().cn;
                  callback(null, cn);
              }
          });
          
          res.on('error', (err) => {
              callback('Error searching user details', null)
          });
          res.on('end', (res) => {
              if (counter == 0) {
                  callback('Error search user details', null);
              }
              
              client.unbind();
          });
      });
  },
  
  //
  // This function checks the credentials against the required LDAP server, 
  // using the correct DN to bind. 
  //
  checkLogin(client, username, password, domain, callback) {
      var bindDN = '';
      var base = '';
  
      switch (domain) {
          case 'unipi.it':
              base = 'dc=dm,ou=people,dc=unipi,dc=it';
              bindDN = "uid=" + username + "," + base;
              break;
          case 'studenti.unipi.it':
              base = 'dc=studenti,ou=people,dc=unipi,dc=it';
              bindDN = "uid=" + username + "," + base;
              break;
          case 'mail.dm.unipi.it':
              base = 'ou=People,dc=student,dc=dm,dc=unipi,dc=it';
              bindDN = "uid=" + username + "," + base;
              break;
          default:
              callback('Invalid domain', null);
              return;
      }
      
      client.bind(bindDN, password, function (err) {
          if (err) {
              callback('Invalid password', null);
          }
          else {
              AuthenticationManager.findUserDetails(client, username, domain, base, callback);
          }
      });
  },
  
  ldapAuth(query, passwd, onSuccess, callback, adminMail, userObj) {
  
      const tlsOpts = {
          checkServerIdentity: function(serverName, cert) {
              return undefined;
          },
          rejectUnauthorized: false
      };

      const starttlsOpts = {
          rejectUnauthorized: true
      };

      const pieces = query.email.split('@');
      const username = pieces[0];
      const domain = pieces[1];

      if (domain == 'mail.dm.unipi.it') {
          const client_dm = ldap.createClient({
              url: process.env.LDAP_SERVER_DM,
              tlsOptions: tlsOpts
          });

          AuthenticationManager.checkLogin(client_dm, username, passwd, domain, function (err, res) {
              if (err == null) {
                  onSuccess(query, adminMail, userObj, res, callback);
              }
              else {
                  callback(null, null);
              }
          });
      }
      else {
          const client = ldap.createClient({
	      url: process.env.LDAP_SERVER,
	  });      
      
          client.starttls(starttlsOpts, client.controls, function (err, res) {
              if (err == null) {
                  AuthenticationManager.checkLogin(client, username, passwd, domain, function (err, res) {
                      if (err == null) {
                          onSuccess(query, adminMail, userObj, res, callback);
                      }
                      else {
                          callback(null, null);
                      }
                  });
              }
              else {
                  callback(null, null);
              }
          });
      }
  },

  // End of custom methods for LDAP auth

  validateEmail(email) {
    const parsed = EmailHelper.parseEmail(email)
    if (!parsed) {
      return new InvalidEmailError({ message: 'email not valid' })
    }
    return null
  },

  // validates a password based on a similar set of rules to `complexPassword.js` on the frontend
  // note that `passfield.js` enforces more rules than this, but these are the most commonly set.
  // returns null on success, or an error object.
  validatePassword(password, email) {
    if (password == null) {
      return new InvalidPasswordError({
        message: 'password not set',
        info: { code: 'not_set' },
      })
    }

    let allowAnyChars, min, max
    if (Settings.passwordStrengthOptions) {
      allowAnyChars = Settings.passwordStrengthOptions.allowAnyChars === true
      if (Settings.passwordStrengthOptions.length) {
        min = Settings.passwordStrengthOptions.length.min
        max = Settings.passwordStrengthOptions.length.max
      }
    }
    allowAnyChars = !!allowAnyChars
    min = min || 6
    max = max || 72

    // we don't support passwords > 72 characters in length, because bcrypt truncates them
    if (max > 72) {
      max = 72
    }

    if (password.length < min) {
      return new InvalidPasswordError({
        message: 'password is too short',
        info: { code: 'too_short' },
      })
    }
    if (password.length > max) {
      return new InvalidPasswordError({
        message: 'password is too long',
        info: { code: 'too_long' },
      })
    }
    if (
      !allowAnyChars &&
      !AuthenticationManager._passwordCharactersAreValid(password)
    ) {
      return new InvalidPasswordError({
        message: 'password contains an invalid character',
        info: { code: 'invalid_character' },
      })
    }
    if (typeof email === 'string' && email !== '') {
      const startOfEmail = email.split('@')[0]
      if (
        password.indexOf(email) !== -1 ||
        password.indexOf(startOfEmail) !== -1
      ) {
        return new InvalidPasswordError({
          message: 'password contains part of email address',
          info: { code: 'contains_email' },
        })
      }
    }
    return null
  },

  setUserPassword(user, password, callback) {
    AuthenticationManager.setUserPasswordInV2(user, password, callback)
  },

  checkRounds(user, hashedPassword, password, callback) {
    // Temporarily disable this function, TODO: re-enable this
    if (Settings.security.disableBcryptRoundsUpgrades) {
      return callback()
    }
    // check current number of rounds and rehash if necessary
    const currentRounds = bcrypt.getRounds(hashedPassword)
    if (currentRounds < BCRYPT_ROUNDS) {
      AuthenticationManager.setUserPassword(user, password, callback)
    } else {
      callback()
    }
  },

  hashPassword(password, callback) {
    bcrypt.genSalt(BCRYPT_ROUNDS, BCRYPT_MINOR_VERSION, function (error, salt) {
      if (error) {
        return callback(error)
      }
      bcrypt.hash(password, salt, callback)
    })
  },

  setUserPasswordInV2(user, password, callback) {
    if (!user || !user.email || !user._id) {
      return callback(new Error('invalid user object'))
    }
    const validationError = this.validatePassword(password, user.email)
    if (validationError) {
      return callback(validationError)
    }
    this.hashPassword(password, function (error, hash) {
      if (error) {
        return callback(error)
      }
      db.users.updateOne(
        {
          _id: ObjectId(user._id.toString()),
        },
        {
          $set: {
            hashedPassword: hash,
          },
          $unset: {
            password: true,
          },
        },
        function (updateError, result) {
          if (updateError) {
            return callback(updateError)
          }
          _checkWriteResult(result, callback)
        }
      )
    })
  },

  _passwordCharactersAreValid(password) {
    let digits, letters, lettersUp, symbols
    if (
      Settings.passwordStrengthOptions &&
      Settings.passwordStrengthOptions.chars
    ) {
      digits = Settings.passwordStrengthOptions.chars.digits
      letters = Settings.passwordStrengthOptions.chars.letters
      lettersUp = Settings.passwordStrengthOptions.chars.letters_up
      symbols = Settings.passwordStrengthOptions.chars.symbols
    }
    digits = digits || '1234567890'
    letters = letters || 'abcdefghijklmnopqrstuvwxyz'
    lettersUp = lettersUp || 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    symbols = symbols || '@#$%^&*()-_=+[]{};:<>/?!£€.,'

    for (let charIndex = 0; charIndex <= password.length - 1; charIndex++) {
      if (
        digits.indexOf(password[charIndex]) === -1 &&
        letters.indexOf(password[charIndex]) === -1 &&
        lettersUp.indexOf(password[charIndex]) === -1 &&
        symbols.indexOf(password[charIndex]) === -1
      ) {
        return false
      }
    }
    return true
  },
}

AuthenticationManager.promises = {
  authenticate: util.promisify(AuthenticationManager.authenticate),
  hashPassword: util.promisify(AuthenticationManager.hashPassword),
  setUserPassword: util.promisify(AuthenticationManager.setUserPassword),
}

module.exports = AuthenticationManager
