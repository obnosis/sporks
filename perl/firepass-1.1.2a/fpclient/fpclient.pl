#!/usr/bin/perl
#
# fpclient.pl - FIREPASS client
# By Alex Dyatlov <alex@gray-world.net>
# Download the latest FIREPASS version at http://gray-world.net/
# This program is distributed under the terms of the GNU General
# Public License v2.0. Read the file COPYING for details.
#
# VERSION 1.1.2a
#
# September, 2003

use IO::Socket;
use strict;

# ----------------------------------- Configuration section - begin
my $http 	= 80;		# Default httpd port
my $httpsep	= "\r\n\r\n";	# HTTP header separator
my $readsize 	= 20480;	# Socket read buffer
my $drt 	= 0;		# Select() timeout at CLIENT and SERVER sockets
my $sidl	= 1;		# Firepass connection close delay on SIGTERM
my $maxses	= 99999;	# Maximum session ID
# ----------------------------------- Configuration section - end

my %CONF;
my %RULES;
my %ACCESS;

$| = 1;

sub tcpconnect(@); sub resolvename(@); sub loop(@);
sub dataready(@); sub checkhttp(@); sub checkconn(@);
sub checkcode(@); sub clearstr(@); sub msleep(@);
sub _sigint(@); sub ebase64($;$); sub _log(@);
sub debug(@);

$CONF{CONFIG} = $ARGV[0];
$CONF{REQUEST} = $ARGV[1];

unless ($CONF{CONFIG} || $CONF{REQUEST}) {
	print "Usage: $0 path_to/config_file host[:port]".
		"/cgi-bin/fpserver.cgi\n\n";
	exit -1;
}

open(F, $CONF{CONFIG})
        or die "\n* error: fail to open config file: $CONF{CONFIG}: $!\n\n";
while (my $s = <F>) {
	$s = clearstr($s);
	if ($s =~ /(\S+)(\s+)(.+)/) {
		my $key = $1;
		my $value = $3;
		$value =~ s/(\s*)$//s;
		$key = uc($key);
		debug("n/a", "\t$key:\t$value");
		$value = 1 if ($value eq "yes"); 
		$value = 0 if ($value eq "no"); 
		$CONF{$key} = $value;
	} else {
		next;
	}
}
close(F);

open(F, $CONF{RULES})
        or die "\n* error: fail to open redirect rules file: ".
		"$CONF{RULES}: $!\n\n";
my $count = 0;
while (my $s = <F>) {
	$s = clearstr($s);
	if ($s =~ /(\d+)\s+((tcp)|(udp))\s+(\S+)\s+(\d+)\s+((tcp)|(udp))/i) {
		(my $lport, my $lproto, my $target, my $tport, my $tproto) =
			($1, $2, $5, $6, $7);
		my $tip = resolvename($target);
		die "\n* error: unable to resolve target hostname $target for ".
			"local port $lport/$lproto\n\n"
			unless (defined($tip));
		$RULES{"$lport:$lproto"} = join(":",($target, $tport, $tproto));
		debug("n/a", "Adding redirect rule: from local port".
			" $lport/$lproto to $tip:$tport/$tproto");
		$count++;
	}
}
close(F);
die "\n* error: no redirect rules was found in $CONF{RULES}\n\n"
	if ($count == 0);

if ($CONF{USEACL}) {
	open(F, $CONF{ACL})
        	or die "\n* error: fail to open access list file: ".
		"$CONF{ACL}: $!\n\n";
	while(my $s = <F>) {
		$s = clearstr($s);
		next
			if ($s !~ /\d+\.\d+\.\d+\.\d+/);
		$s =~ s/(\s*)$//s;
		$ACCESS{$s} = 1;
		debug("n/a", "Adding $s to access list");
	}
	close(F);
} else {
	debug("n/a", "Access list is not in use");
}

if ($CONF{REQUEST} =~ /^([^\/]+)(.*)/s) {
	$CONF{HOST} = $1;
	$CONF{REQUEST} = $2;
	if ($CONF{HOST} =~ /([^:]+):(.*)/) {
		$CONF{HOST} = $1;
		$CONF{PORT} = $2;
	}
} else {
	die "\n* error: unable to parse hostname from $ARGV[0]\n\n";
}

$CONF{IP} = resolvename($CONF{HOST});
die "\n* error: unable to resolve hostname $CONF{HOST}\n\n"
	unless (defined($CONF{IP}));
$CONF{PORT} = $http
	unless ($CONF{PORT});
	
if ($CONF{PROXY}) {
	die "\n* error: proxyip is not specified in $CONF{CONFIG}\n\n"
		unless ($CONF{PROXYIP});
	die "\n* error: proxyport is not specified in $CONF{CONFIG}\n\n"
		unless ($CONF{PROXYPORT});
	if ($CONF{PROXYRESOLVE}) {
		$CONF{REQUEST} = "http://$CONF{HOST}:$CONF{PORT}$CONF{REQUEST}";
	} else {
		$CONF{REQUEST} = "http://$CONF{IP}:$CONF{PORT}$CONF{REQUEST}";
	}
	$CONF{IP} = $CONF{PROXYIP};
	$CONF{PORT} = $CONF{PROXYPORT};
}

my $ttype;
if ($CONF{PROXY}) { $ttype = "proxy"; } else { $ttype = "httpd"; }
debug("n/a", "Server script: $CONF{REQUEST}");
debug("n/a", "Target host: $CONF{IP}:$CONF{PORT} / $ttype");

_log("Firepass client starts");
_log("Config file $CONF{CONFIG}");
_log("Server script $CONF{REQUEST}");

$SIG{CHLD} = "IGNORE";

if ($CONF{DEMONIZE}) {
	exit 0
		if (fork());
	debug("n/a", "Firepass demonized");
}

my %SOCKDESC;
my @S	= undef;
my $sc	= 0;
my $rulez;
foreach my $key (sort keys %RULES) {
	(my $port, my $proto) = split(/:/, $key);
	my %OPTIONS = (
		LocalPort => $port,
		Reuse     => 1,
		Proto     => $proto
	);
	$OPTIONS{Listen} = $CONF{LISTEN}
		if ($proto =~ /tcp/i);
	$S[$sc] = IO::Socket::INET->new(%OPTIONS)
		or die "\n* error: fail to bind on $port/$proto: $!\n\n";
	$S[$sc]->autoflush(1);
	$SOCKDESC{$S[$sc]} = $RULES{$key};
	debug("n/a", "Listening socket $S[$sc] created for $port/$proto");
	$sc++;
}

debug("n/a", "Starting endless loop");

my $SERVER = undef;
my $CLIENT;
my $SOCKET;
my $session = 0;
my $counter = 0;
push(@S, undef);
while (1) {
	$session++;
	$session = 1
		if ($session > $maxses);
	$CLIENT = IO::Socket::INET->new;
	$SOCKET = dataready(@S);
	my $addr = accept($CLIENT, $SOCKET);
	$CLIENT->autoflush(1);
	my $cip = $CLIENT->peerhost();
	my $cport = $CLIENT->peerport();
	my $sport = $SOCKET->sockport();
	debug($session,
		"Accepting connection from CLIENT $CLIENT ($cip:$cport)");
	_log("client \#$session: connection from $cip:$cport to local port ".
		"$sport");
	if ($CONF{USEACL} && !exists($ACCESS{$cip})) {
		debug($session,
			"No record for CLIENT $CLIENT ($cip) in access list");
		close($CLIENT);
		next;
	}
	$rulez = $SOCKDESC{$SOCKET};
	if (fork() == 0) {
		debug($session,
			"Connection Manager created for CLIENT $CLIENT");
		loop();
		exit 0;
	}
	close($CLIENT);
}

sub tcpconnect(@) {
	my ($ip, $port, $to) = @_;
	my $S = IO::Socket::INET->new(
		PeerAddr => $ip,
		PeerPort => $port,
		Proto    => "tcp",
		Type     => SOCK_STREAM,
		Timeout  => $to)
			or die
			"\n* error: fail to connect to $ip:$port: $!\n\n";
	$S->autoflush(1);
	return $S;
}

sub resolvename(@) {
	my $host = shift;
	my $ip;
	if ($host !~ /\d+\.\d+\.\d+\.\d+/) {
		(my $name, my $aliases, my $addrtype, my $length, my @addrs) =
			gethostbyname($host)
			or return undef;
		$ip = join('.', unpack('C4', $addrs[0]));
	} else {
		$ip = $host;
	}
	return $ip;
}

sub loop(@) {
	my $cbuf = my $sbuf = "";
	my $cbytes = my $sbytes = 0;
	my $ctotal = my $stotal = 0;
	$SIG{INT} = \&_sigint;
	while (1) {
		my $data;
		my $datalength;
		my $datasize;
		my $datasend = 0;
		$sbuf = "";
		$sbytes = 0;
		my $flag = 0;
		my $err = 0;
		$counter++;
		msleep($CONF{DELAY})
			if ($CONF{DELAY} > 0);
		if ($SERVER == undef) {
			$SERVER = tcpconnect($CONF{IP}, $CONF{PORT},
				$CONF{TIMEOUT});
			debug($session,
				"Target $CONF{IP}:$CONF{PORT} connected");
		}
		while (dataready($CLIENT, $drt)) {
			my $bytes = sysread($CLIENT, my $buf, $readsize);
			if ($bytes > 0) {
				$cbuf = $cbuf.$buf;
				$cbytes += $bytes;
				$ctotal += $bytes;
			} else {
				debug($session, "CLIENT $CLIENT is dead");
				_log("client #$session: Disconnected, ".
					"$stotal bytes received from server ".
					"/ $ctotal bytes sent");
				sendmsg($SOCKET, "", 0, "close");
				close($CLIENT);
				close($SERVER);
				exit 0;
			}
			debug($session, "Receive from CLIENT: $cbytes bytes");
		}
		my $r = sendmsg($SOCKET, $cbuf, $cbytes, "alive");
		debug($session, "Sending $cbytes bytes to SERVER $SERVER")
			if ($cbytes > 0);
		unless ($r) {
			debug($session,
				"Fail to send HTTP msg to SERVER $SERVER");
			next;
		}
		while (dataready($SERVER, undef)) {
			my $bytes = sysread($SERVER, my $buf, $readsize);
			if ($bytes == 0 || $bytes == undef) {
				debug($session,
				       "Connection to SERVER $SERVER was lost");
				close($SERVER);
				$SERVER = undef;
				$counter--;
				$err = 1;
				last;
			} 
			debug($session, "Receive from SERVER: $bytes bytes");
			$sbytes += $bytes;
			$sbuf = $sbuf.$buf;
			if ($flag == 0) {
				my $code = checkcode($sbuf);
				if (defined($code)) {
					if ($CONF{DROP}) {
						debug($session, "HTTP error: ".
							"$code; Shutdowning");
						shutdown($SERVER, 2);
						shutdown($CLIENT, 2);
						exit(0);
					}
					debug($session, "HTTP error: $code; ".
				  	 "Reconnecting in $CONF{ERRDELAY} sec");
					$counter--;
					$err = 1;
					msleep($CONF{ERRDELAY})
						if ($CONF{ERRDELAY} > 0);
					last;
				}
				($data, $datalength, $datasize) =
					checkhttp($sbuf);
				next
					unless ($datasize>-1 && $datalength>-1);
				unless (checkconn($sbuf)) {
					_log("client #$session: Target server ".
				  	     "close connection; $stotal bytes ".
					     "received from server / $ctotal ".
					     "bytes sent");
					debug($session,
					      "Target server close connection");
					shutdown($CLIENT, 2);
					shutdown($SERVER, 2);
					exit(0);
				}
				last
					unless ($datalength > 0);
				next
					unless($datasize > 0);
				$sbuf = $data;
				$bytes = $datasize;
				$flag = 1;
			} 
			print $CLIENT $sbuf;
			debug($session, "Sending $bytes bytes CLIENT $CLIENT");
			$stotal += $bytes;
			$datasend += $bytes;
			$sbytes = 0;
			$sbuf = "";
			last
				if ($datasend == $datalength);
		}
		if ($err == 0) {
			$cbytes = 0;
			$cbuf = "";
		}
	}
}

sub dataready(@) {
	my @s = @_;
	my $to = $s[$#s];
	$#s--;
	my $rin = "";
	foreach my $d (@s) {
		vec($rin, fileno($d), 1) = 1;
	}
	my $nfound = select(my $rout = $rin, undef, my $eout = $rin, $to);
	foreach my $d (@s) {
		return $d
			if (vec($eout, fileno($d), 1) ||
				vec($rout, fileno($d), 1));
	}
	return 0;
}

sub checkhttp(@) {
	my $m = shift;
	if ($m =~ /(.*?)$httpsep(.*)/s) {
		my $h = $1;
		my $b = $2;
		if ($h =~ /Content-Length: (\d+)/i) {
			my $c = $1;
			return ($b, $c, length($b));
		}
	}
	return ('', -1, -1);
}

sub checkconn(@) {
	my $m = shift;
	if ($m =~ /(.*?)$httpsep(.*)/s) {
		my $h = $1;
		return 0
			if ($h =~ /X-Connection: close/i);
	}
	return 1;
}

sub checkcode(@) {
	my $m = shift;
	my $code;
	if ($m =~ /(.*?)\r/) {
		$code = $1;
		return $code
			if ($code =~ /^[^ ]+ [45]/s);
	}
	return undef;
}

sub sendmsg(@) {
	my ($SOCKET, $cbuf, $cbytes, $conn) = @_;
	my $header =  join("\r\n",
		"POST $CONF{REQUEST} HTTP/1.1",
		"Content-Type: application/octet-stream",
		"User-Agent: $CONF{AGENT}",
		"Host: $CONF{HOST}",
		"Content-Length: $cbytes",
		"X-Session: $session",
		"X-Counter: $counter",
		"X-Connection: $conn"
	);
	if ($counter == 1 && $conn ne "close") {
		(my $host, my $port, my $proto) = split(":", $rulez);
		debug($session, "Asking server script to build connection at ".
			"$host:$port/$proto");
		$header = join("\r\n", $header,
			"X-Host: $host",
			"X-Port: $port",
			"X-Proto: $proto"
		);
	}
	if ($CONF{AUTH}) {
		my $auth_str = ebase64("$CONF{USER}:$CONF{PASS}", "");
		$header = join("\r\n", $header,
			"Authorization: Basic $auth_str"
		);
	}
	if ($CONF{PROXY} && $CONF{PROXYAUTH}) {
		my $auth_str = ebase64("$CONF{PROXYUSER}:$CONF{PROXYPASS}", "");
		$header = join("\r\n", $header,
			"Proxy-Authorization: Basic $auth_str"
		);
	}
	$header = join("\r\n", $header,
		"Proxy-Connection: Keep-alive",
		"Pragma: no-cache")
		if ($CONF{PROXY});
	my $msg = join($httpsep, $header, $cbuf);
	print $SERVER $msg
		or return undef;
	
	return 1;
}

sub clearstr(@) {
	my $s = shift;
	chomp($s);
	$s =~ s/(\s+)?#(.*)?//;
	return $s;
}

sub msleep(@) {
	my $i = shift;
	select(undef, undef, undef, $i);
	return;
}

sub _sigint(@) {
	my $sig = shift;
	if ($SERVER) {
		debug($session, "Closing connection on SIGNAL $sig");
		sendmsg(undef, "", 0, "close");
	}
	msleep($sidl) if ($sidl > 0);
	exit 0;
}

sub ebase64 ($;$) {
	my $res = "";
	my $eol = $_[1];
	$eol = "\n" unless defined $eol;
	pos($_[0]) = 0;
	while ($_[0] =~ /(.{1,45})/gs)
		{$res .= substr(pack('u', $1),1);chop($res);}
	$res =~ tr|` -_|AA-Za-z0-9+/|;
	my $padding = (3 - length($_[0]) % 3) % 3;
	$res =~ s/.{$padding}$/'=' x $padding/e if $padding;
	if (length $eol) {$res =~ s/(.{1,76})/$1$eol/g;}
        $res;
}


sub _log(@) {
	my $s = shift;
	return unless($CONF{LOG});
	(my $sec, my $min, my $hour, my $day, my $month, my $year) = 
		(localtime)[0,1,2,3,4,5];
	$year += 1900;
	$month++;
	open(FH, ">> $CONF{LOGF}")
        	or die "\n* error: fail to open log file: $CONF{LOGF}: $!\n\n";
	my $date = sprintf("%4d/%02d/%02d [%02d:%02d:%02d]",
		$year, $month, $day, $hour, $min, $sec);
	print FH "$date $s\n";
	close(FH);
	return;
}

sub debug(@) {
	my ($session, $s) = @_;
	return unless ($CONF{DEBUG});
	my ($sec, $min, $hour, $day, $month, $year) = (localtime)[0,1,2,3,4,5];
	my $date = sprintf("[%02d:%02d:%02d]", $hour, $min, $sec);
	print STDERR "$date \#$session: $s\n";
	return;
}
