Installation:
After cloning the repository, begin installation by using 'npm init'
It will install all the neccessary files and modules required to run the server.

Then after installing, we can run the server by using 'npm start' command.

Server routes:
/register : User can register themselves by using a username and password;
/login: User can login after registering.
/dashboard: User can access this route after logging in successfully.
/logout: User can logout from this route.

Approach:
I approached this project by listing the routes first, and for each route the steps required to complete it. 
Register route requires password validation, hashing, creating jwt tokens and storing them as cookies. 
Login route requires password validation, checking if password matches from the database and handling tokens like generating accesstoken if expired from refresh token.
Logout route contains removing the token from cookies.
Dashboard contains verifying if the tokens are correct or missing and generating accesstoken from refresh token.

Challenges faced:
A challenge I faced was how to store the tokens. We can also store them on server side in database. But I chose to store them in cookies, to reduce the number of queries done to the server, which can help in scaling the project further.

Ensuring Security:
I ensured security by validating passwords. They must be bigger than 6 characters, with atleaset 1 uppercase, 1 lowercase, 1 number and 1 special character.
While querying I used '?' instead of variables. This can stop SQL injection attacks, as it contains user filled information it cannot be trusted.