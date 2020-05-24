# letsencrypt_glassfish
A script to simplify the installation and maintenance of Letsencrypt certificates in glassfish or payara web servers.

This script is intended to simplify the installation of a Let's Encrypt certificate in a glassfish/payara server and provide an automated way of renewing that certificate when it is about to expire.

There exists a significant amount of documentation on the web which addresses this problem but I have found much of it to be ambiguous and incomplete.  This is an attempt to remove that ambiguity and incompleteness by giving a real world working example which can be modified to suit a particular situation.

The script itself is heavily commented.  At the time of this writing, only 261 of 621 lines are actually code.  Please refer to the comments in the code for detailed directions on usage.
