# Open password management API
<b>Open password management</b> is an open-source <b>WebAPI</b> created for people who don't want to keep their sensitive data
in external servers, but wants to have remote access to them. It's an open code under MIT license which means that you are welcome to 
adjust it just as you would like.<br>
<b>You need to create a client application,</b> so it's a great opportunity to do it exactly as you would want to! 
It's also a great testing ground for beginning frontend programmers, because you can focus on your favourite job - I did the rest :)<br>

## Features
List of all features available in API:

 - Creating a user account.
 - Editing user account data, such as changing the password, as well as the ability to delete the account.
 - Safe storage of user login data.
 - Option to edit and delete selected login data.
 - Help in generating a new, strong password.
 - Password strength checking.
 - Integration with the [haveibeenpwned.com](https://haveibeenpwned.com) service to check if the password used by the user isn't present in the stolen passwords databases.
 - Generating a backup of user data (in the form of an unencrypted json file). 

## Swagger API documentation
Swagger documentation of API is aviable at endpoint `/api/Docs`.

## Database
OPM uses the noSQL MongoDB database. The API uses two collections (the SQL table equivalents). The "accounts" collection 
contains information about user accounts and their login credentials for other sites, while the "sessions" collection 
stores info about their sessions.

The encryption of selected fields in the table was enabled by the CSFLE (Client-Side FieldLevel Encryption) mechanism 
recently added by the creators of MongoDB. It allowed for "semi-transparent" (transparent decryption is free, and 
transparent encryption when adding items to the database is part of a paid subscription) encryption (with the 
AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic algorithm) of sensitive data in the database using a properly configured 
client version. Fields marked as encrypted use this mechanism. 

#### Collection "accounts"

    {
        "_id": ObjectId,
        "email": string (encrypted field),
        "login": string (encrypted field),
        "password": string (encrypted field),
        "loginData": [
            {
                "_id": ObjectId,
                "site": string,
                "login": string (encrypted field),
                "password": string (encrypted field),
                "passwordStrength": int,
                "note": string
            }
        ]
    }

#### Collection "sessions"

    {
        "_id": ObjectId,
        "token": string,
        "last_used": date,
        "public_key_PEM": string
    }

## Security features

Security of communication is ensured by the following measures:
- Passwords and logins send during registration and logging in are additionally encrypted with RSA. 
- All other communication are additionally encrypted with AES-GCM along with RSA (so you don't need HTTPS or can have another layer of encryption). 
- User sessions are kept by the use of tokens that user will get from the server each time they log into the application.
- The tokens will have a limited validity period, updated after each activity 

Security of the server and database will be ensured by: 
- Access to the system only after correct user identification. 
- The user's login data to the OPM and to third parties are stored in the database in encrypted form using the CSFLE mechanism.

## Deployment

API is ready for deployment at any server. You just need to run it with uwsgi.ini (probably configuring it a bit before) using command `uwsgi uwsgi.ini`.

If you want to try it by Internet but don't have personal server and/or domain you can deploy it to any PaaS.
The OPM API has been tested on [Heroku](https://heroku.com) and it's ready for deployment there. I even left the `Procfile`,
so you only need to upload this project to Heroku.
I also tested the free version of MongoDB Atlas to provide a 512MB cloud cluster for database storage. Choosing this 
solution made the integration with Heroku much easier, because there was no need to store the database itself on the 
Heroku (what is a bit tricky) or host it on my server. Thanks to both of these solutions the server and database are available for use every 
day, around the clock :D