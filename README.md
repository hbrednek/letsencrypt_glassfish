# letsencrypt_glassfish
A script to simplify the installation and maintenance of Let's Encrypt certificates in Glassfish and Payara web servers.

This script is intended to simplify the installation of a Let's Encrypt certificate in a glassfish/payara server and provide an automated way of renewing all Let's Encrypt certificates on the server.

There exists a significant amount of documentation on the web which addresses this problem but I have found much of it to be ambiguous and incomplete.  This is an attempt to remove that ambiguity and incompleteness by giving a real world working example which can be modified to suit a particular situation.

What I've done is broken the process of obtaining a Let's Encrypt certificate into the following steps, a few of which may not actually be necessary:

1. Customize the script to the particular local installation
   1. List of domains for which a certificate is to be created
   1. Glassfish/Payara setup (where they're located in your filesystem)
   1. Password for Glassfish/Payara
1. Change Glassfish/Payara to listen on ports 80 and 443
1. Generate the Let's Encrypt certification keys
1. Insure that the keystore password matches that of the server
1. Create a keystore
1. Import the created keystore into the Glassfish/Payara keystore
1. Apply the new certificate to the https listener
1. Update the domain SSL information
1. Set (if necessary) the server admin password.
1. Set up the https domain

Additionally, the script can be invoked periodically (typically via 'cron') to check to see if any domains need to be renewed and if so, renew them automatically.

I have used this script to create a new certificate for three domains in less than 5 minutes.  I have used this script to automatically renew three domains via a cron job.

Good luck! Let me know if you have any problems. Mike Elliott - mre@m79.net
