#!/bin/perl
#
# fpserver.cgi - FIREPASS server
# By Alex Dyatlov <alex@gray-world.net>
# Download the latest FIREPASS version at http://gray-world.net/
# This program is distributed under the terms of the GNU General Public License v2.0
# See the file COPYING for details
#
# VERSION 1.1.2a
#
# September, 2003
#
# ------------------------------------------- Configuration section - begin
my $config_file = "fpcnf.cache";# Config cache file
my $inm = "_in.dat";		# Exchange files masks
my $outm = "_out.dat";		# ..
my $lockm = ".lock";		# Lock files mask
my $faketype = "text/html";
my $fakepage = qq (
<html>
<body></body>
</html>
);				# HTML page for browsers requests
my $verbose	= 1;		# Verbose mode for the script console usage
my $readsize    = 20480;        # Socket read buffer
my $defhttp	= 80;		# Default HTTP port
# --------------------------------------------- Configuration section - end

use strict;
use IO::Socket;
use Fcntl ':flock';

sub forkmanager(@); sub proxymode(@); sub dataready(@);
sub checkcode(@); sub closeses(@); sub configure(@);
sub debug(@); sub msleep(@); sub _read(@);
sub _write(@); sub touch(@); sub clearstr(@);
sub ebase64 ($;$); sub _logerror(@); sub _log(@);

my %CONF;
my %ACCESS;
my $script = $0;

$| = 1;

my ($action, $orig_conf) = @ARGV;

if ($action eq "configure") {
	if (scalar(@ARGV) < 2) {
		debug("main", "config file is not specified");
		debug("main", "$0 configure path/to/fpserver.conf\n");
		exit -1;
	}
	configure($ARGV[1]);
}

my $session = $ENV{HTTP_X_SESSION};
my $counter = $ENV{HTTP_X_COUNTER};
my $rip	    = $ENV{REMOTE_ADDR};
my $rport   = $ENV{REMOTE_PORT};

open(F, $config_file) or die "firepass server not configured";
read(F, my $c, -s $config_file);
close(F);
eval($c);

unless (defined($session)) {
	_log("parent", "n/a", "connection from $rip:$rport without session id");
	print "Content-Type: $faketype\r\n\r\n";
	print "$fakepage";
	exit 0;
}

if ($CONF{USEACL}) {
	_logerror("parent", $session, "no access list record for $rip")
		unless (exists($ACCESS{$rip}));
}

if ($CONF{FIREPROXY}) {
	proxymode();
	exit 0;
}

my $fin = "$CONF{INOUTDIR}/$session$inm";
my $fout = "$CONF{INOUTDIR}/$session$outm";

if ($counter == 1) {
	my $host  = $ENV{HTTP_X_HOST};
	my $port  = $ENV{HTTP_X_PORT};
	my $proto = $ENV{HTTP_X_PROTO};
	_logerror("parent", $session, "redirect host, port or protocol missed")
		if ($host !~ /\S+/ || $port !~ /\d+/ || ($proto !~ /tcp/i && $proto !~ /udp/i));
	_log("parent", $session, "connection from $rip:$rport; redirecting to $host:$port/$proto");
	_logerror("parent", $session, "fail to create files in $CONF{INOUTDIR}/ directory: $!")
		unless (open(IH, "> $fin") && open(OH, "> $fout"));
	close(IH);
	close(OH);
	$SIG{CHLD} = "IGNORE";
	my $child = forkmanager($session, $host, $port, $proto);
	_logerror("parent", $session, "fail to fork Connection Manager for $rip")
		if ($child == undef);
	msleep($CONF{INITDELAY})
		if ($CONF{INITDELAY} > 0);
}

if ($ENV{HTTP_X_CONNECTION} eq "close") {
	msleep($CONF{CHECKDELAY})
		while (-s $fout > 0);
	closeses();
	_log("parent", $session, "connection from $rip:$rport closed");
	print "Content-Length: 0\r\n".
		"X-Connection: close\r\n".
		"\r\n";
	exit 0;
}

unless (-e $fin && -e $fout) {
	print "Content-Length: 0\r\n".
		"X-Connection: close\r\n".
		"\r\n";
	exit 0;
}

if ($ENV{CONTENT_LENGTH} > 0) {
	read(STDIN, my $buf, $ENV{CONTENT_LENGTH});
	my $bw = _write($fout, $buf);
	_logerror("parent", $session, "fail to write into $fout")
		if ($bw == undef);
} else {
	touch($fout);
}

my $size = -s $fin;
print "Content-Type: application/octet-stream\r\n".
      "X-Connection: alive\r\n";
if ($size == 0) {
	print "Content-Length: $size\r\n".
	      "\r\n";	
}
if ($size > 0) {
	my $buf = _read($fin);
	print "Content-Length: ".(length($buf))."\r\n".
	      "\r\n";	
	print $buf;
}

exit 0; # main() end

sub forkmanager(@) {
	(my $session, my $host, my $port, my $proto) = @_;
	my $f = fork();
	if ($f == 0) {
		close(STDIN);
		close(STDOUT);
		close(STDERR);
		my $SOCKET = IO::Socket::INET->new(
			PeerAddr => $host,
			PeerPort => $port,
			Proto    => $proto,
			Type     => SOCK_STREAM
		);
		if ($SOCKET == undef) {
			_log("child", $session, "connection fail to $host:$port/$proto");
			msleep($CONF{CHECKDELAY})
				while (-s $fin > 0);
			closeses();
			exit 0;
		}
		my $stotal = my $ctotal = 0;
		while (1) {
			unless (-e $fin && -e $fout) {
				_log("child", $session, "connection from client closed; $stotal".
					" bytes received from target / $ctotal bytes sent");
				shutdown($SOCKET, 2);
				exit 0;
			}
			my $d = dataready($SOCKET, $CONF{CHECKDELAY});
			my $size = -s $fout;
			if ($d == $SOCKET) {
				my $bytes = sysread($SOCKET, my $buf, $readsize);
				if ($bytes == 0) {
					_log("child", $session,
						"connection from target closed; $stotal".
						" bytes received from target / $ctotal bytes sent");
					msleep($CONF{CHECKDELAY})
						while (-s $fin > 0);
					closeses();
					exit 0;
				}
				$stotal += $bytes;
				_write($fin, $buf);
			}
			if ($size > 0) {
				my $buf = _read($fout);
				$ctotal += length($buf);
				print $SOCKET $buf;
			} else {
				my $mtime = (stat($fout))[9];
				if ($CONF{SESSIONTO} > 0 && (time() - $mtime) > $CONF{SESSIONTO}) {
					_log("child", $session,
						"connection closed due to timeout exceed; $stotal".
						" bytes received from target / $ctotal bytes sent");
					closeses();
					exit 0;
				}
			}
		}
	}
	return $f;
}

sub proxymode(@) {
	my $uri  = $CONF{NEXTSERVER};
	my $ip   = $CONF{NEXTPROXYIP};
	my $port = $CONF{NEXTPROXYPORT};
	my $host;
	_log("parent", $session, "proxy mode: from $rip:$rport to $uri")
		if ($counter == 1);
	unless ($CONF{NEXTPROXY}) {
		if ($uri =~ /http:\/\/([^\/]+)(.*)/s) {
			$host = $1;
			$uri = $2;
			if ($host =~ /([^:]+):(.*)/) {
				$host = $1;
				$port = $2;
			} else {
				$port = $defhttp;
			}
		} else {
			_logerror("parent", $session,
				"fail to parse target firepass server URI");
		}
		$ip = $host;
	}
	my $SOCKET = IO::Socket::INET->new(
		PeerAddr => $ip,
		PeerPort => $port,
		Proto    => "tcp",
		Type     => SOCK_STREAM
	);
	unless (defined($SOCKET)) {
		_logerror("parent", $session,
			"connection fail to firepass server $ip:$port");
	}
	my $header = join("\r\n",
		"POST $uri HTTP/1.0",
		"Content-Type: application/octet-stream",
		"Connection: close",
		"X-Session: $session",
		"X-Counter: $counter",
		"X-Connection: $ENV{HTTP_X_CONNECTION}"
	);
	$header = join("\r\n", $header,
		"Host: $host") unless ($CONF{NEXTPROXY});
	$header = join("\r\n", $header,
		"Proxy-Connection: close") if ($CONF{NEXTPROXY});
	if ($CONF{NEXTSERVERAUTH}) {
                my $auth_str = ebase64("$CONF{NEXTSERVERUSER}:$CONF{NEXTSERVERPASS}", "");
		$header = join("\r\n", $header,
			"Authorization: Basic $auth_str"
		);
	}
	if ($CONF{NEXTPROXY} && $CONF{NEXTPROXYAUTH}) {
		my $auth_str = ebase64("$CONF{NEXTPROXYUSER}:$CONF{NEXTPROXYPASS}", "");
		$header = join("\r\n", $header,
			"Proxy-Authorization: Basic $auth_str"
		);
	}
	if ($counter == 1 && $ENV{HTTP_X_CONNECTION} ne "close") {
		$header = join("\r\n", $header,
			"X-Host: $ENV{HTTP_X_HOST}",
			"X-Port: $ENV{HTTP_X_PORT}",
			"X-Proto: $ENV{HTTP_X_PROTO}"
		);
	}
	my $size = 0;
	my $buf;
	if ($ENV{CONTENT_LENGTH} > 0) {
		$size = read(STDIN, $buf, $ENV{CONTENT_LENGTH});
	}
	$header = join("\r\n", $header,
		"Content-Length: $size",
		"\r\n"
	);
	print $SOCKET $header;
	print $SOCKET $buf
		if ($size > 0);
	my $res = <$SOCKET>;
	my $code = checkcode($res);
	if (defined($code)) {
		_logerror("parent", $session,
			"HTTP request to $uri fail : $code");
	}
	my $cl = 0;
	while (my $s = <$SOCKET>) {
		last if ($s =~ /^\s+$/s);
		if ($s =~ /^Content-Length: (\d+)/i) {
			$cl = $1;
			print "Content-Type: application/octet-stream\r\n".
				"Content-Length: $cl\r\n";
		}
		if ($s =~ /^X-Connection: (\S+)/) {
			my $conn = $1;
			print "X-Connection: $conn\r\n";
		}
	}
	print "\r\n";
	if ($cl > 0) {
		while (<$SOCKET>) {
			print;
		}
	}
	close($SOCKET);
	return;
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
			if (vec($eout, fileno($d), 1) || vec($rout, fileno($d), 1));
	}
	return 0;
}

sub checkcode(@) {
	my $m = shift;
        my $code;
	if ($m =~ /(.*?)\r/) {
		$code = $1;
		return $code
			if ($code !~ /^[^ ]+ 200/s);
	}
	return undef;
}


sub closeses(@) {
	unlink($fin) if (-e $fin);
	unlink($fout) if (-e $fout);
	unlink("$fin$lockm") if (-e "$fin$lockm"); 
	unlink("$fout$lockm") if (-e "$fout$lockm");
	return;
}

sub configure(@) {
	my $orig_conf = shift;
	debug("\nconfigure", "start");
	unless (open(F, $orig_conf)) {
		debug("configure",
			"opening config file $orig_conf ...failed\n".
			" (?) not enough privilegies or bad file name\n");
		exit -1;
	}
	debug("configure", "opening config file $orig_conf ...ok");
	unless (open(C, "> $config_file")) {
		debug("configure",
			"creating config cache file $config_file ...failed\n".
			" (?) not enough privilegies or bad file name\n");
		exit -1;
	}
	debug("configure", "creating config cache file $config_file ...ok");
	my $count = 0;
	while (my $s = <F>) {
		$s = clearstr($s);
		if ($s =~ /(\S+)(\s+)(.+)/) {
			$count++;
			my $key = $1;
			my $value = $3;
			$value =~ s/(\s*)$//s;
			$key = uc($key);
			$value = 1 if ($value eq "yes");
			$value = 0 if ($value eq "no");
			$CONF{$key} = $value;
			$value = "\"$value\""
				if ($value =~ /[ a-zA-Z\/]/ ||
					$value =~ /\d+\.\d+\.\d+\.\d+/);
			print C "\$CONF{$key} = $value;\n";
		} else {
			next;
		}
	}
	close(F);
	debug("configure", "$count options added to the config cache file");
	my $test = "configure.test";
	unless(open(T, "> $CONF{INOUTDIR}/$test")) {
		debug("configure",
			"creating test file in the data exchange directory ...failed\n".
			" (?) not existing directory or not enough privilegies to ".
			"create $CONF{INOUTDIR}/$test\n");
		exit -1;
	}
	debug("configure", "creating test file in the data exchange directory ...ok");
	close(T);
	unlink("$CONF{INOUTDIR}/$test");
	if ($CONF{USEACL}) {
		unless(open(F, $CONF{ACL})) {
			debug("configure", "opening access list file $CONF{ACL} ...failed\n".
				" (?) not enough privilegies or bad file name\n");
			exit -1;
		}
		while(my $s = <F>) {
			$s = clearstr($s);
			next
				if ($s !~ /\d+\.\d+\.\d+\.\d+/);
			$s =~ s/(\s*)$//s;
	                print C "\$ACCESS{\"$s\"} = 1;\n";
		}
		close(F);
		debug("configure", "opening access list file $CONF{ACL} ...ok");
	} else {
		debug("configure", "opening access list file ...skipped");
	}
	if ($CONF{LOG} && !(-e "$CONF{LOGDIR}/$CONF{LOGF}")) {
		unless(open(T, "> $CONF{LOGDIR}/$CONF{LOGF}")) {
			debug("configure",
				"creating test file in the log directory ...failed\n".
				" (?) not existing directory or not enough privilegies to ".
				"create $CONF{LOGDIR}/$CONF{LOGF}\n");
			exit -1;
		}
		debug("configure", "creating test file in the log directory ...ok");
		close(T);
		unlink("$CONF{LOGDIR}/$CONF{LOGF}");
	} else {
		debug("configure", "creating test file in the log directory ...skipped");
	}
	close(C);
	debug("configure", "done\n");
	exit 0;
}

sub debug(@) {
	my ($src, $msg) = @_;
	print STDERR "$src: $msg\n"
		if ($verbose);
	return;
}

sub msleep(@) {
	my $i = shift;
	select(undef, undef, undef, $i);
	return;
}

sub _read(@) {
	my $file = shift;
	my $buf;
	open(RLOCK, "> $file$lockm")
		or return undef;
	flock(RLOCK, LOCK_EX);
	open(RH, "+< $file")
		or return undef;
	flock(RH, LOCK_EX);
	my $size = -s $file;
	my $br = read(RH, $buf, $size);
	open(RH, "> $file")
		or return undef;
	close(RH);
	close(RLOCK);
	return $buf;
}

sub _write(@) {
	my ($file, $buf) = @_;
	open(WLOCK, "> $file$lockm")
		or return 0;
	flock(WLOCK, LOCK_EX);
	open(WH, ">> $file")
		or return 0;
	flock(WH, LOCK_EX);
	print WH $buf;
	close(WH);
	close(WLOCK);
	return 1;
}

sub touch(@) {
	my @files = @_;
	my $t = time;
	utime($t, $t, @files);
	return;
}

sub clearstr(@) {
	my $s = shift;
	chomp($s);
	$s =~ s/(\s+)?#(.*)?//;
	return $s;
}

sub ebase64 ($;$) {
	my $res = "";
	my $eol = $_[1];
	$eol = "\n" unless defined $eol;
	pos($_[0]) = 0;
	while ($_[0] =~ /(.{1,45})/gs) {$res .= substr(pack('u', $1),1);chop($res);}
	$res =~ tr|` -_|AA-Za-z0-9+/|;
	my $padding = (3 - length($_[0]) % 3) % 3;
	$res =~ s/.{$padding}$/'=' x $padding/e if $padding;
	if (length $eol) {$res =~ s/(.{1,76})/$1$eol/g;}
	$res;
}


sub _logerror(@) {
	my ($src, $session, $s) = @_;
	print "Content-Length: 0\r\n".
		"X-Connection: close\r\n".
		"\r\n"
		if ($src eq "parent" && $session ne "n/a");
	_log($src, $session, "error: $s");
	exit 0;
}

sub _log(@) {
	my ($src, $session, $s) = @_;
	return unless ($CONF{LOG});
	(my $sec, my $min, my $hour, my $day, my $month, my $year) = (localtime)[0,1,2,3,4,5];
	$year += 1900;
	$month++;
	open(FH, ">> $CONF{LOGDIR}/$CONF{LOGF}");
	flock(FH, LOCK_EX);
	my $date = sprintf("%4d/%02d/%02d [%02d:%02d:%02d]", $year, $month, $day, $hour, $min, $sec);
	print FH "$date $src [\#$session] $s\n";
	close(FH);
	return;
}
