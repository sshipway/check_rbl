#!/usr/bin/perl
#
# check_rbl : check that the IP is not on any of the RBL lists
#             DO NOT run this more often than every 1 hour since it would
#             cause undue load on the RBL servers
#
# Steve Shipway, University of Auckland, 2006
# http://www.steveshipway.org/software
#
# Usage:  check_rbl ip-address
#
# Version: 1.1 - Parameter can be hostname as well as IP address.
#          1.2 - add uceprotect, remove dead lists, add blacklist check
#                add a few more additional lists, add debug mode to identify
#                slow blacklists; whitelist support; fix hostname bug in 1.1
#          1.3 - some updates to list details
#          1.4 - add the nixspam blacklist
#          1.5 - set target=_new on links
#                add emailreg.org

use strict;
my($VERSION) = "1.5";
my($IP,$PFX);
my($MSG,$STATUS);
my($DOM,$URL,$DESC);
my($rv);

my($DEBUG) = 0;

##############################################################################
# Blacklists
my( @BLACKLISTS ) = (
	# DNS blackhole domain, name, optional website address
# NJABL has now been superceded by pbl.spamhaus
#	[ "combined.njabl.org",        "NJA Blacklist", "http://www.njabl.org/" ],
# OpenRBL now only allow HTTP queries, and rate limit them, so we cant check
# them using this plugin.
#	[ "openrbl.org",        "OpenRBL Blacklist", "http://www.openrbl.org/" ],
# This one is very reliable, always check this as it is widely used
	[ "dnsbl.sorbs.net",           "SORBS", "http://www.sorbs.net/" ],
	[ "spam.dnsbl.sorbs.net",           "SORBS Spamlist", "http://www.sorbs.net/" ],
# This one is very reliable, always check this as it is widely used
	[ "zen.spamhaus.org",      "Spamhaus SBL/XBL/PBL", "http://www.spamhaus.org/" ],
# This one is either too slow or not longer in existance
#	[ "list.dsbl.org",             "Distributed Sender", "http://dsbl.org/" ],
# Always check this as it is widely used
	[ "fuldom.rfc-ignorant.org",   "RFC-Ignorant", "http://www.rfc-ignorant.org/" ],
# Always check this as it is widely used
	[ "bl.spamcop.net",            "SpamCop", "http://www.spamcop.net/" ],
# These are more rarely used
	[ "bogons.cymru.com",            "Cymru", "http://www.cymru.com/" ],
	[ "blackholes.intersil.net",     "Intersil", "http://www.intersil.net/" ],
	[ "spam.spamrats.com",     "Spamrats", "http://www.spamrats.com/" ],
	[ "psbl.surriel.com",     "Surriel", "http://www.surriel.com/" ],
# These are a bit aggressive
#	[ "bl.spamcannibal.org",            "SpamCannibal", "http://www.spamcannibal.org/" ],
# This one can be slow; comment it out if necessary
	[ "rbl.efnet.org",     "Efnet", "http://www.efnet.org/" ],
	[ "spamguard.leadmon.net",     "Leadmon", "http://www.leadmon.net/" ],
# This one is very widely used in US universities
	[ "b.barracudacentral.org",     "Barracuda", "http://www.barracudacentral.org/rbl/" ],
# These people also host a whitelist, and brownlist...
	[ "hostkarma.junkemailfilter.com",     "IGetNoSpam", "http://wiki.ctyme.com/index.php/Spam_DNS_Lists" ],
# This list costs E50 to get off; not very reliable
	[ "dnsbl-1.uceprotect.net",   "UCEProtect", "http://www.uceprotect.net/" ],
#	[ "dnsbl-2.uceprotect.net",   "UCEProtect(lvl2)", "http://www.uceprotect.net/" ],
#	[ "dnsbl-3.uceprotect.net",   "UCEProtect(lvl3)", "http://www.uceprotect.net/" ],
# This list costs E50 to get off; not very reliable (actually is uceprotect)
#	[ "ips.backscatterer.org",     "Backscatterer", "http://www.backscatterer.org/" ],
	[ "blackholes.mail-abuse.org", "Mail-abuse.org", "http://www.mail-abuse.org/" ],
	[ "ix.dnsbl.manitu.net", "nixSPAM", "http://www.dnsbl.manitu.net/" ],
    [ "resl.emailreg.org", "EmailReg.org", "http://www.emailreg.org/" ],
# These people only allow HTTPS queries
#   [ "proofpoint.com", "ProofPoint", "https://support.proofpoint.com/" ],
);

##############################################################################
# Functions
sub checkdom($) {
	my($n,$a,$at,$l,@ad) = gethostbyname($PFX.".".$_[0]);
	my(@addr);
	return 0 if(!$n);
	@addr = unpack('C4',$ad[0]);
	return $addr[3];
}

##############################################################################
# MAIN

shift @ARGV if($ARGV[0] and $ARGV[0] eq '-H');
if(!$ARGV[0]) {
	print "Usage: check_rbl ipaddress\n";
	exit 3; # Unknown
}
if( $ARGV[0]=~/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/ ) {
	$PFX = "$4.$3.$2.$1";
	$IP = $ARGV[0];
} else {
	# Resolve a host name
	my ( $lhname, $aliases, $addrtype, $length,  @addrs)
         = gethostbyname( $ARGV[0] );
 	$IP = join '.',unpack('C4',$addrs[0]);
	if(!$IP) {
		print "Hostname ".$ARGV[0]." does not resolve.\n";
		exit 3;
	}
	$IP=~/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/ ;
	$PFX = "$4.$3.$2.$1";
}

$STATUS = 0; $MSG = "";
foreach ( @BLACKLISTS ) {
	($DOM,$DESC,$URL) = @$_;
	if($DEBUG) { print "".localtime()." Checking $DESC\n"; }
	$rv = checkdom($DOM);
	if($rv==1) {
		$MSG .= "<BR>" if($MSG);
		$MSG .= "Whitelisted on ";
		$MSG .= "<A HREF=\"$URL\" TARGET=\"_new\" >" if($URL);
		$MSG .= $DESC;
		$MSG .= "</A>" if($URL);
		print "".localtime()." FOUND\n" if($DEBUG);
#	}elsif($rv==2) { # Use this if you want brownlists - unreliable with sorbs
	}elsif($rv>1) {  # use this normally
		$MSG .= "<BR>" if($MSG);
		$MSG .= "Listed on ";
		$MSG .= "<A HREF=\"$URL\" TARGET=\"_new\" >" if($URL);
		$MSG .= $DESC;
		$MSG .= "</A>" if($URL);
		$STATUS = 2; # Critical!
		print "".localtime()." FOUND\n" if($DEBUG);
	} elsif($rv) {
		$MSG .= "<BR>" if($MSG);
		$MSG .= "Listed on ";
		$MSG .= "<A HREF=\"$URL\" TARGET=\"_new\" >" if($URL);
		$MSG .= $DESC;
		$MSG .= "</A>" if($URL);
		$MSG .= "($rv)";
		$STATUS = 1 if(!$STATUS); # Warn 
		print "".localtime()." FOUND\n" if($DEBUG);
	} else {
		print "".localtime()." OK\n" if($DEBUG);
	}
}

if(!$MSG) { 
	$MSG = "";
	foreach ( @BLACKLISTS ) {
		($DOM,$DESC,$URL) = @$_;
		$MSG .= ", " if($MSG);
		$MSG .= $DESC;
	}
	$MSG = "All OK: $MSG";
}
$MSG .= " <BR><A HREF=\"http://www.blacklistalert.org/?q=$IP\" TARGET=\"_new\" >Check blacklists</A>";
$MSG .= "<BR>check_rbl version $VERSION";

print "$MSG\n";
exit $STATUS;
