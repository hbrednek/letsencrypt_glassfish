#!/usr/bin/perl

###################################################################
# 
# Copyright 2019 - 2021
#
# Michael R. Elliott Software Engineering and Computer Forensics
#
# Licensed under the Creative Commons License.
#
# This document may be copied, distributed, edited, remixed and
# built upon by anyone, including commercial users.
#
###################################################################
# 
# This script is intended to simplify the installation of a Let's
# Encrypt certificate in a Glassfish/Payara server and provide an
# automated way of renewing all Let's Encrypt certificates about to
# expire.
#
# There exists a significant amount of documentation on the web which
# addresses this problem but I have found much of it to be ambiguous
# and incomplete.  This is an attempt to remove that ambiguity and
# incompleteness by giving a real world working example which can be
# modified to suit a particular situation.
#
# The script is designed to be located in the glassfish/payara config
# directory.  In my installation that is:
#
# /opt/payara5/glassfish/domains/domain1/config
#
# Note that all steps shown may not actually apply to your
# implementation.  Judiciously skip those which don't apply.  There
# may even be steps which are unnecessary.  I don't really know.
# However, if there are, they're at least harmless.  If you find an
# unnecessary step, please let me know!
#
# Examine all the values up to the Actions section, modifying them as
# fits your individual implementation.  In particular, change the value
# of $execute_command to $true to actually do something other than show
# what would be done if you allowed it.
#
# Note well:
# As delivered, the script DOES ABSOLUTELY NOTHING!  This is intentional
# as initially, all actions have been commented out!  The recommended
# technique is to uncomment each step, observe what it will do, then
# actually do that.  For example, Step 1 sets the incoming ports to 80
# and 443.  That will almost certainly be done at most one time, while
# generating certificates - especially if new domains are added, may be
# done multiple times - and checking for certificate renewal may well be
# done daily or weekly.  So, un-comment the actions which you need to
# execute and re-comment those which will not be needed in the near
# future.
#
# Two important problems were encountered in the creation of this
# script:
#
# 1) I was initally using a version of Java which was incompatible.
#    Unfortunately, I didn't get around to checking the server log
#    file for way too long (exceptions were being thrown).  This
#    upgrading of the Java version necessary to get past this problem
#    is not addressed by this script.  Let this be a warning to you:
#    closely monitor the server log file.  If your installation is
#    throwing exceptions, fix that problem first.
#
# 2) I switched to payara half way through the script's development.
#    However payara has (had?) a problem with VNC's which prevented it
#    from running.  I had to initially start my host (a Raspberry Pi)
#    without a VNC and then change the payara runtime environment.
#    You may need to start payara from an SSH shell then disable
#    hazelcast (the problematic payara service) via:
#
#    asadmin set-hazelcast-configuration --enabled=false
#
# Please send any comments or corrections to mre@m79.net.  I REALLY
# want this to work for everyone using a UNIX variant like Linux.  If
# you're a Windows user, best of luck to you. I'm not a Windows person
# so my knowledge of your domain is minimal. However, perhaps this can
# give you something to adapt to your environment.  If you make some
# variant of this work for you in Windows, please let me know!
#
# Note 1: that at the end of this script is a subroutine which can be
# used for certificate renewal, which has to be done every 90 days
# (or less) - but that's only after you've managed to create and
# install the initial certificate.
#
# Note 2: I have successfully used this script to create certificates
# for multiple domains in less than five minutes.  Additionally, it
# has been used to successfully renew those certificates from a cron
# job with no manual intervention.
#
# Sample crontab entries:
#
#     CONFIG=/opt/payara5/glassfish/domains/domain1/config
#     LELOG=/tmp/letsencrypt.log
#     12 4 * * * root \
#        (cd $CONFIG && /root/letsencrypt_glassfish.pl renew >> $LELOG)
#   
# ----
# Installation control
#
# These can be set to just show the commands to be executed, to
# execute only, or to show and execute.  Initial value is to only show
# the commands without executing them.
#
my ($true, $false) = (1, 0);
my $print_cmd = $true;
my $execute_cmd = $false; # Change this to actually do something!

# ----
# Target domain stuff.  
#
# The list of domains which are to be made usable through TLS.  Add
# all your domains here. These were mine as of January 2020. It's OK
# if this list contains only one domain, but it must contain at least
# one domain.  Otherwise, there's nothing for which a cert can be
# generated.
#
my @domains = qw/
   m79.net
   oc-water.com
   unixforensic.com
/;

# ----
# Glassfish/Payara and certbot stuff
#
# These need to be set to reflect your particular installation
#
my $certbot = "/usr/bin/certbot";
my $glassfish_base = "/opt/payara5/glassfish";
my $asadmin = "$glassfish_base/bin/asadmin";

# These values should probably not be changed.  Do so only if you really
# know what you're doing.
#
my $keystore_jks = "keystore.jks";
my $cacerts_jks = "cacerts.jks";
my $domain_name = "domain1";
my $http_listener = "http-listener-1";
my $https_listener = "http-listener-2";
my $domain_path = "$glassfish_base/domains/$domain_name";
my $config = "$domain_path/config";

# This is the password of both the server and the keystore.  The
# default is 'changeit'.  The two need to have the same password.
# This password will be used throughout this script.  I have retained
# the default, perhaps unwisely, but at the time I wrote this script
# this is the situation.  If you change this password and it works for
# you, please let me know!
#
my $password = 'changeit';

# ----
# Let's Encrypt stuff
#
# This is the name used to specify this set of certificates.  Here
# it's the first domain in the domain list.  Let's Encrypt typically
# uses the name of a domain as the place to store the certificates,
# but it might be confusing if multiple certificates are listed.  This
# resolves that potential ambiguity.
#
my $cert_name = $domains[0];

# These values are almost certainly correct as written.  Change only
# under unusual circumstances.
#
my $letsencrypt_base = "/etc/letsencrypt/live/$cert_name";
my $certificate_public_key = "$letsencrypt_base/fullchain.pem";
my $certificate_private_key = "$letsencrypt_base/privkey.pem";

# These values are arbitrary, but known to work.
#
my $pkcs12_file = "pkcs.p12";
my $certificateNickName = $domain_name . "cert";

# ------------------------------------------------------------------------
# Validiations

# Before we go any further, confirm that the script can find asadmin.
#
die "Can't find asadmin in $glassfish_base\n" unless -e $asadmin;

# This script is intended to be run in the domain's config directory.
# It will check to see that that is the case before continuing.
#
die "Script must be run in $config\n" unless confirm_config_directory();

# ------------------------------------------------------------------------
# Actions

# The following steps have been found to be useful.  Note that all are
# initially disabled.  Some steps may not be necessary in your
# particular situation.  If so, feel free to skip them. For those not
# Perl knowledgable, the # character denotes the beginning of a
# comment.  The lines beginning with ## are the ones which are to be
# selectively activated.
#
# Check the documentation for a particular subroutine for more details
# about that step.  Note that if you only want to see what the
# generated command actually is, rather than immediately running it,
# you can set the variable $execute_cmd to '$false' and the variable
# $print_cmd to $true to see the generated command without actually
# executing it.
#
# In order to enable a step, uncomment the requisite subroutine.  I
# recommend that you initially do this step by step, carefully
# observing the result at each step, before going to the next step.
#
# ========
# Step 1
# Change glassfish/payara to listen on ports 80 and 443 rather than the
# default.  By default, glassfish/payara creates http-listener-1 and
# http-listener-2 on 8080 and 8181.
#
# *****
## listen_port( $http_listener, 80 );
## listen_port( $https_listener, 443 );

# ========
# Step 2
# Generate the Let's Encrypt certificate keys in webroot mode. Make
# sure that the server is running and listening on port 80 before
# running this.
#
# *****
## generate_webroot_letsencrypt_keys();

# ========
# Step 3
# Change the keystore password to match that of the glassfish/payara
# server.  This is probably not necessary, but included here for
# completeness.
#
# *****
## system change_keystore_password();

# ========
# Step 4
# Create a keystore
#
# *****
## create_pkcs12_file();

# ========
# Step 5
# Import the created keystore into the Glassfish/Payara keystores
#
# *****
## import_PKCS_to_keystore( $keystore_jks );
## import_PKCS_to_keystore( $cacerts_jks );

# ========
# Step 6
# Apply new certificate to https listener
#
## apply_certificate();

# ========
# Step 7
# Update the $glassfish_domain SSL information
#
## update_SSL();

# ========
# Step 8
# If necessary, set the admin password.  This should only be done if
# the admin password is the default (empty) password.
#
## set_admin_password();

# ========
# Step 9
# Set up the https domain.  Note: this consists of steps which must be
# manually executed.
#
## set_https_domain();

# ------------------------------------------------------------------------
# Subroutines.
#
# You shouldn't have to modify any of the following subroutines as
# written.  If you feel the need to modify any of these routines,
# please let me know as others may have encountered the same situation.

# Invoke certbot (which needs to already be installed) placing
# authentication artifacts in the server's docroot directory in order
# to generate a set of certificate keys. Getting certbot is left as an
# exercise for the reader, but I managed to get it with 'apt-get
# install certbot'.
#
# This is to be executed when glassfish/payara is running
#
sub generate_webroot_letsencrypt_keys {
    die "Server is not running on port 80\n"
        unless server_is_running( 80 );

    my $docroot = "$domain_path/docroot";
    die "Can't find docroot at $docroot\n"
        unless -d $docroot;

    pre_cert_access();
    print_execute(
        "$certbot certonly"
        . " --webroot"
        . " --webroot-path $docroot"
        . " --cert-name $cert_name"
        . " -d " . join( " -d ", @domains ) );
    post_cert_access();
}

# Invoke certbot (which needs to already be installed) in standalone
# mode in order to generate a set of certificate keys.
#
sub generate_standalone_letsencrypt_keys {
    die "Server is running on port 80\n" if server_is_running( 80 );
    print_execute(
        "$certbot certonly"
        . " --standalone"
        . " --cert-name $cert_name"
        . " -d " . join( " -d ", @domains )
        );
    print "Make sure the server is running"
        . " after this action has completed\n";
}

# Configure a network listener to listen on a specific port
#
# Usage:
#
#    listen_port( "$http-listener", 80 );
#
# will cause $http-listener to listen on port 80.
#
sub listen_port {
    my $network_listener = shift;
    my $port = shift;

    print "-- Setting $network_listener to listen on $port\n\n";
    print_execute(
        "$asadmin set configs.config.server-config" 
        . ".network-config.network-listeners" 
        . ".network-listener.$network_listener"
        . ".port=$port"
        );
}

# Change the password of the keystore.
#
sub change_keystore_password() {
    print "-- Changing keystore $keystore_jks password to $password\n\n";
    print "-- The expected password is $password\n"
        . "Change as necessary:\n\n";
    print_execute( "keytool -storepasswd -keystore $keystore_jks" );
}

# Create PKCS.p12 file with key and certificate
#
sub create_pkcs12_file() {
    print "-- Creating pkcs12_file in $pkcs12_file\n";
    print "-- Expected password is $password\n\n";
    print_execute(
        "openssl pkcs12 -export" 
        . " -in $certificate_public_key" 
        . " -inkey $certificate_private_key" 
        . " -out $pkcs12_file" 
        . " -name $certificateNickName"
	. " -passin pass:$password"
	. " -passout pass:$password"
        );
}

# Import the created keystore ($pkcs12_file) into one of the
# existing server keystores.
#
sub import_PKCS_to_keystore( $ ) {
    my $keystore = shift;
    print "-- Importing the created keystore ($pkcs12_file)" .
	" into $keystore\n\n";
    print_execute( 
        "keytool -importkeystore"
	. " -noprompt"
        . " -srckeystore $pkcs12_file"
        . " -srcstorepass $password"
        . " -srcstoretype PKCS12"
        . " -destkeystore $keystore"
        . " -deststorepass $password"
        . " -alias $certificateNickName"
        );
}

# Set the admin password for the server.
#
sub set_admin_password() {
    print "-- ";
    print "Setting admin password. Default is the empty password";
    print "\n\n";
    print_execute(
        "$asadmin change-admin-password"
        );
}

# Update the server's SSL configuration.
#
sub update_SSL() {
    my $asadmin_prefix =
        "$asadmin set configs"
        . ".config.server-config.network-"
        . "config.protocols.protocol.$https_listener.";

    print "-- Update server SSL listener\n\n";
    print_execute(
        $asadmin_prefix . "security-enabled=true"
        );
    print_execute(
        $asadmin_prefix . "ssl.tls-enabled=true"
        );
    print_execute(
        $asadmin_prefix . "ssl.tls11-enabled=true"
        );
    print_execute(
        $asadmin_prefix . "ssl.tls12-enabled=true"
        );
}

# Apply certificate to $https_listener.
#
sub apply_certificate {
    print "-- Apply certificate to listener $https_listener\n\n";
    print_execute(
        "asadmin set"
        . " configs.config.server"
        . "-config.network"
        . "-config.protocols.protocol."
        . $https_listener
        . ".ssl.cert"
        . "-nickname=$certificateNickName"
        );
}

# Provide user instructions as to how (through the administration
# console page) the user can set the https domain.
#
sub set_https_domain {
    print "-- ";
    print "Using the admin console, access Configurations"
        . "\n--   -> default-config"
        . "\n--   -> HTTP Service"
        . "\n--   -> Http listeners"
        . "\n--   -> $https_listener"
        . "\n";
    print "\n-- Then, using the SSL tab\n"
        . "--   set the Certificate NickName to $certificateNickName\n"
        . "--   and the Key Store to $keystore_jks\n"
        . "--   then Save\n";
    print "\n Using the admin console, access Configurations"
        . "\n--   -> server-config"
        . "\n--   -> HTTP Service"
        . "\n--   -> Http listeners"
        . "\n--   -> $https_listener"
        . "\n";
    print "\n-- Then, using the SSL tab\n"
        . "--   set the Certificate NickName to $certificateNickName\n"
        . "--   then Save\n";
}

# Determine whether something (presumably the server) is listening on
# the given port.
#
sub server_is_running {
    my $port = shift;
    open( PROC, "netstat -ltnp | grep -w ':$port' |" );
    my $line = <PROC>;
    chomp $line;
    my $result = $line =~ /$port/;
    close PROC;
    return $result;
 }

# Confirm that the script is running in the config directory
#
sub confirm_config_directory {
    my $result = $false;
    open( PWD, "pwd |" );
    my $line = <PWD>;
    chomp $line;
    $result = $line =~ /^$config$/;
    close PWD;
    return $result;
}

# Print the command and/or execute it
#
sub print_execute {
    my $cmd = shift;
    if ($print_cmd) {
        if ($execute_cmd) {
            print "# $cmd\n\n";
        }
        else {
            print "-- Command: $cmd\n";
        }
    }
    system $cmd if $execute_cmd;
}

###########################################################
# Domain renewal routines
###########################################################

# Return a list of domains needing renewal.
#
# Takes a single parameter indicating days remaining until renewal.
# Default is 28.
#
sub domains_to_renew {
    my $days = shift;
    my $max_days = 28;
    $days = $max_days unless defined $days;

    my @result = ();
    my $cert_name = "";
    my $expiry = 1000;
    open( CERTBOT, "$certbot certificates 2>&1 |" );
    while (<CERTBOT>) {
        if (m/\s+Certificate Name:\s+(.*)/) {
            $cert_name = $1;
            $expiry = 1000000;
        }
        if (m/\s+Expiry.*?(\d+) days/) {
            $expiry = $1;
            push @result, $cert_name if $expiry <= $days;
        }
        
    }
    close CERTBOT;
    return @result;
}

# Decide if there are domains needing renewal and if so, renew them.
#
# Note well: Certificate renewal should be done only if all the
# subroutines used to create the certificate in the first place are
# commented out!
#
sub check_and_renew {
    # This can be run by specifying a parameter (renew) to the script.
    # This subroutine forces the values of $print_cmd and $execute_cmd
    # to false and true, respectively, to be more friendly in an
    # automated environment.
    #
    # An example crontab entry is:
    #
    #  0 4 * * * (cd <path to config> && ./letsencrypt_glassfish.pl renew)
    #
    # which will run this script daily at 4 a.m. to renew any domains
    # close to expiry.  Running daily is probably overkill but it does
    # work.  Weekly is probably good enough.
    #
    $print_cmd = $false;
    $execute_cmd = $true;

    my @domains_to_renew = domains_to_renew();
    if ((scalar @domains_to_renew) > 0) {
        print "[letsencrypt_glassfish] Renewing @domains_to_renew\n";
	pre_cert_access();
        system "$certbot renew";
	post_cert_access();
	reinstall_certificate();
    }
    else {
        print "[letsencrypt_glassfish] No domains need renewal\n";
    }
}

# Sometimes renewals must be forced, as in the recent problem caused
# by a bug in the Letsencrypt security code in early 2020.  In that
# case, renewals must be forced without concern for how long they are
# currently valid.
#
# This routine will execute a forced renewal, and can be activated
# from the command line by adding the command line argument
# "force-renew".
#
sub force_renew {
    # This can be run by specifying a parameter (force-renew) to the
    # script execution.
    #
    $print_cmd = $true;
    $execute_cmd = $true;

    pre_cert_access();
    print_execute( "$certbot renew --force-renewal" );
    post_cert_access();
    reinstall_certificate();
    print "[letsencrypt_glassfish] certbot force renewal completed\n";
}

# Return a list of all current applications about which glassfish is
# aware, regardless of whether they're enabled or disabled.
# 
sub list_all_applications {
    my @result;
    open( APPS, "$asadmin list-applications --type web |" )
	or die "Can't fetch applications\n";
    while (<APPS>) {
	next unless $_ =~ /^(.+?)\s+<web>/;
	push @result, $1;
    }
    close APPS;
    return @result;
}

# Disable all current applications.  Note that this is a fairly big
# hammer - all known applications will be disabled whether or not they
# were already disabled.
#
sub pre_cert_access {
    foreach (list_all_applications()) {
	print_execute( "$asadmin disable $_" );
    }
}

# Re-enable all applications.  Again, a big hammer, but this is
# probably the right solution for the majority of installations.
# However, if your installation has applications which are known to
# glassfish but which should not be re-enabled, this subroutine will
# need to be modified accordingly.
#
sub post_cert_access {
    foreach (list_all_applications()) {
	print_execute( "$asadmin enable $_" );
    }
}

# Gather together all the steps needed to reinstall the certificate into
# a separate subroutine.  Execute this when updating a certificate.
#
sub reinstall_certificate {
    create_pkcs12_file();
    import_PKCS_to_keystore( $keystore_jks );
    import_PKCS_to_keystore( $cacerts_jks );
    apply_certificate();
    update_SSL();
    print_execute( "$asadmin restart-domain $domain_name" );
}

# Check to see if the command has as its first argument the string
# 'renew'.  If it does, attempt to renew all domains which are within
# the necessary time for renewal window.
#
check_and_renew() if defined $ARGV[0] && $ARGV[0] eq 'renew';

# Check to see if the command has as its first argument the string
# 'force-renew'.  If it does, force renewal of all domains.
#
force_renew() if defined $ARGV[0] && $ARGV[0] eq 'force-renew';
