# **START GUIDE:**

#1.
Install Docker Desktop & MongoDB Compass - Download an Authenticator app on your phone [Google Authenticator and Microsoft Authenticator are confirmed working]

#2.
Open powershell and run: (or direct to the project root folder in code environment and run in a powershell terminal:) docker-compose up --build

Allow for the containers to fully build, may take some time

Check progress in docker desktop - when finished should see a stack called "446proj" with a green status next to it
(Can click the dropdown to check on individual containers)

#3.1
If the status is a half-shaded circle, click into the stack and see which container failed
By clicking the container directly, you can access the logs and see exactly what failed where

#3.2
If everything launched correctly, open MongoDB Compass and click "+ Add new connection"
Use the default URI (should direct to localhost:27017) and click "Save and Connect"

This should bring up a few dropdown menus, the one you're interested in is "dashboardDb"
Click on this to reveal the folder "users" - This is where you'll track added users on your machine

#4
In order to launch the dashboard on HTTPS, open the certificates page on your browser (usually Settings -> "search certificate" -> View Certificates -> Import Certificate
Now in the project root folder, direct to nginx/certs and grab the privkey.pem file - Import this into your browser certificates and FULLY shut down your browser (highly suggest killing it in task manager then relaunching)

#5
Type the URL: "https://localhost/" and hit enter - this should bring you to the login page

From here, you can click the "register account" button and create a new account - these credentials will get saved into the MongoDB database

Enter the credentials again, then scan the QR code with your authenticator app to check the 2FA and enter the dashboard
