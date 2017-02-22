#!/usr/bin/perl -w
use Socket;
use IO::Socket;
use POSIX qw(strftime);
#use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);


#
# SYNOPSIS:
#
#	at_server [working dir] [port]
#
#	will default to [working_dir=/home] and [port=33033]
#

my $filebits 	= '';

my $working_dir = shift || '/home';
my $port 		= shift || 33033;

sub SEEK_SET {0;}
sub SEEK_CUR {1;}
sub SEEK_END {2;}

# demonize our process
demonize();

# check for running hydras
print_ts("killed previous hydra") if check_env();
print_ts("hydra has started");

# set environment
set_env();

# the protocol
my %almp = (
	at_msg		=> 'AT_MSG',
	at_end		=> 'AT_END',
	at_bye		=> 'AT_BYE',
	at_term		=> 'AT_TERM',
	at_logs		=> 'AT_LOGS',
	at_filter	=> 'AT_FILTER',
	at_services => 'AT_SERVICES'
);

#
# register signal handler
#
$SIG{INT}	= sub {dehydrate(); clean_env(); exit;}; # server terminated
$SIG{USR1}	= sub {dehydrate(); exit;}; # server killed by other server


#open my $debug_file, '>', '/home/.hydra_log' || die $!;
#select((select($debug_file), $|=1)[0]);

#
# Main Loop
#
my $rout;
open_server();
while(1) {
	#
	# process sockets
	#
	select($rout = $filebits, undef, undef, 1);
	my $routs = unpack("b*", $rout);
	my $pos = index($routs, '1');
	while($pos >= 0) {
		handle_file($pos);
		$pos = index($routs, '1', $pos+1);
	}
	
	#
	# check for updates
	#
	# FIXME: why select()'ing these will result in false positives when size didn't change?
	#
	check_for_service_updates();
	check_for_watched_but_unoppened_logs();
	check_for_log_updates();
}


#
# fb_set
#
sub fb_set {
	my($fileno) = @_;
	vec($filebits,$fileno,1) = 1;
}


#
# fb_unset
#
sub fb_unset {
	my($fileno) = @_;
	vec($filebits,$fileno,1) = 0;
}


#
# open_server
#
sub open_server {
	$server = IO::Socket::INET->new(Listen => 10,
									LocalPort => $port,
									Reuse => 1,
									ReuseAddr => 1,
									Timeout => 0,
									Proto => 'tcp' );
	
	die "Could not create socket $!" unless $server;
	
	$server->blocking(0);
	$server_fileno = fileno($server);
	fb_set($server_fileno);
}


#
# close_server
#
sub close_server {
	fb_unset($server_fileno);
	$server->close();
	undef $server;
}

#
# handle_file
#
sub handle_file {
	local($fileno) = @_;
	
	# FIXME: why this order can't be changed?
	
	#if($logs{$fileno}) {
	#	handle_log($fileno);
	#}
	if($connections{$fileno}) {
		handle_client($fileno);
	}
	elsif($fileno == $server_fileno) {
		handle_server();
	}
	else {
		print_ts("weird fileno $fileno");
	}
}


#
# handle_server
#
sub handle_server {
	my $client = $server->accept();
	
	if($client) {
		my $fileno = fileno($client);
		$client->blocking(0);
		$connections{$fileno}{client} = $client;
		fb_set($fileno);
		print_ts("client($fileno) connected");
	}
	else {
		print_ts("no accept for server, reopen");
		close_all_clients();
		close_server();
		open_server();
	}
}


#
# handle_client
#
sub handle_client {
	my($fileno) = @_;
	
	recv($connections{$fileno}{client},$receive,200,0);
	if($receive) {
		my $line = $connections{$fileno}{buffer};
		$line .= $receive;
		while($line =~ s/(.*)\n// && $connections{$fileno}) {
			my $temp = $1;
			$temp =~ tr/\r\n//d;
			process_client_message($fileno,$temp);
		}
		# save unprocessed data
		if($connections{$fileno}) {
			$connections{$fileno}{buffer} = $line;
		}
	}
	else {
		close_client($fileno);
	}
}

#
# check_for_log_updates
#
sub check_for_log_updates {
	foreach(keys %logs) {
		my $fileno = $_;
		my $path = $logs{$fileno}{path};
		
		my $new_size = -s $path || 0;
		if($new_size != $logs{$fileno}{pos}) {
			# check for log rotation
			if($new_size < $logs{$fileno}{pos}) {
				unless($fileno = reopen_log($fileno)) {
					print_ts("error: could not reopen \"$path\"");
					next;
				}
			}
			handle_log($fileno);
		}
	}
}


#
# handle_log
#
sub handle_log {
	my($fileno)	= @_;
	my $path 	= $logs{$fileno}{path};
	my $fh 		= $logs{$fileno}{fh};
	my $buffer	= $logs{$fileno}{buffer} || '';
	my $new_text;
	
	#
	# read log
	#
	sysseek $fh, $logs{$fileno}{pos}, SEEK_SET; #re-seek to current position
	$buffer.=$new_text while(sysread($fh,$new_text,200,0));
	
	# save current file size
	$logs{$fileno}{pos} = sysseek $fh, 0, SEEK_CUR;
	
	#
	# extract all complete lines
	#
	my $msg = '';
	while($buffer =~ s/(.*)\n//) {
		my $tmp = $1;
		$tmp =~ tr/\r//d;
		next unless length $tmp;
		$msg .= "$tmp\n";
	}
	
	# save unprocessed log text
	$logs{$fileno}{buffer} = $buffer;

	# check if we got anything
	return unless length $msg;
	
	my $watchers = get_watchers($path);
	
	# send updates
	broadcast_update($watchers, $path, \$msg);
}


#
# get_watchers
#
sub get_watchers {
	my($path) = @_;
	return \%{$logpaths{$path}{watchers}};
}


#
# close_client
#
sub close_client {
	my($fileno) = @_;
	
	close_client_logs($fileno);
	
	#
	# disconnect
	#
	fb_unset($fileno);
	$connections{$fileno}{client}->close();
	delete $connections{$fileno};
	print_ts("client($fileno) disconnected");
}


#
# close_all_clients
#
sub close_all_clients {
	close_client($_) foreach(keys %connections);
}


#
# send_message
#
sub send_message {
	my($fileno, $msg) = @_;
	
	if($connections{$fileno}) {
		my $client = $connections{$fileno}{client};
		print $client "$$msg\n";
	}
}


#
# broadcast_message
#
sub broadcast_message {
	my($watchers,$msg) = @_;
	foreach(keys %{$watchers}) {
		send_message($_,$msg);
	}
}


#
# broadcast_update
#
sub broadcast_update {
	my($watchers,$path,$msg) = @_;
	
	# extract file name
	$path =~ /\/(\w*\/[a-zA-Z.-]*)$/;
	my $file_name = $1 || $path;
	
	foreach(keys %{$watchers}) {
		my $client_fileno = $_;
		#
		# filter log text
		#
		my $tmp = $$msg;
		if($connections{$_}{filter}) {
			filter_text($connections{$_}{filter}, $path, \$tmp);
			my $tmp2 = $tmp;
			# make sure the message isn't all empty spaces and newlines
			$tmp2 =~ s/(\s|\n)*//sg;
			next unless length $tmp2;
		}
		# format message
		$tmp = "\n\n$file_name:\n\n$tmp";
		#send_message($client_fileno, \$almp{at_msg});
		send_message($client_fileno, \$tmp);
		#send_message($client_fileno, \$almp{at_end});
		
		#print $debug_file $tmp;
	}
}


#
# process_client_message
#
sub process_client_message {
	my($fileno, $msg) = @_;
	
	return unless $msg;
	
	my $client = \%{$connections{$fileno}};
	
	#
	# process ALMP messages
	#
	if(is_almp($msg)) {
		# AT_FILTER
		if(test_almp($msg,at_filter)) {
			# reset current filter
			delete $client->{filter};
			delete $client->{filter_is_exclusive};
		}
		# AT_LOGS
		elsif(test_almp($msg,at_logs)) {
			# reset current log list
			delete $client->{logs};
		}
		# AT_SERVICES
		elsif(test_almp($msg,at_services)) {
			# reset current service list
			delete $client->{services};
			delete $client->{got_services};
		}
		# AT_BYE
		elsif(test_almp($msg, at_bye)) {
			close_client($fileno);
			return;
		}
		# AT_TERM
		elsif(test_almp($msg, at_term)) {
			kill 2 => $$;
			return;
		}
		# AT_END
		elsif(test_almp($msg, at_end) && $client->{curr_op}) {
			# AT_FILTER
			if(test_almp($client->{curr_op},at_filter)) {
				# set-up filter
				if($client->{filter}) {
					$client->{filter} = preproc_filter($client->{filter});
					$client->{filter_is_exclusive} = is_exclusive($client->{filter});
				}
				# rescan logs
				if($client->{got_logs}) {
					close_client_logs($fileno);
					send_log_list($fileno, find_logs($fileno));
				}
			}
			# AT_LOGS
			elsif(test_almp($client->{curr_op},at_logs)) {
				$client->{got_logs} = 1;
				close_client_logs($fileno);
				send_log_list($fileno,find_logs($fileno));
			}
			# AT_SERVICES
			elsif(test_almp($client->{curr_op},at_services)) {
				$client->{got_services} = 1;
			}
			# consume message
			$msg = undef;
		}
		
		# keep track of current operation
		$client->{curr_op} = $msg;
	}
	#
	# process actual data
	#
	elsif($client->{curr_op}) {
		# AT_FILTER
		if($client->{curr_op} eq $almp{at_filter}) {
			$client->{filter} .= "$msg\n" unless $msg =~ /^(\s)*$/;
		}
		# AT_LOGS
		elsif($client->{curr_op} eq $almp{at_logs}) {
			push @{$client->{logs}}, $msg;
		}
		# AT_SERVICES
		elsif($client->{curr_op} eq $almp{at_services}) {
			push @{$client->{services}}, $msg;
		}
	}
}


#
# dehydrate
#
# gracefully exit
#
sub dehydrate {
	print_ts("dehydrating...");
	close_all_clients();
	close_server();
}


#
# is_almp
#
sub is_almp {
	my ($str) = @_;
	foreach( keys %almp ) {
		return 1 if test_almp($str,$_);
	}
	return 0;
}


#
# test_almp
#
sub test_almp {
	my($str,$key) = @_;
	#print_ts('test_almp('.$key.')');
	return $str eq $almp{$key};
}


#
# demonize process
#
sub demonize {
	use POSIX qw(setsid);
	chdir '/'
		or die "Can't chdir to /: $!";
	open STDIN, '/dev/null'
		or die "Can't read /dev/null: $!";
	open STDOUT, ">>", "$working_dir/.at_status"
		or die "Can't write to .at_status: $!";

	defined(my $pid = fork)
		or die "Can't fork: $!";

	exit if $pid;

	setsid
		or die "Can't start a new session: $!";

	open STDERR, ">>", "$working_dir/.at_err"
		or die "Can't write to .at_err: $!";
	
	# make STDOUT unbuffered
	select((select(STDOUT), $|=1)[0]);
}


#
# check for existing hydra and kill it
#
sub check_env {
	# see if lock file exists
	if( -e "$working_dir/.at_server" ) {
		#
		# kill hydra
		#
		open my $fh, "$working_dir/.at_server"
			or die "Couldn't open .at_server: $!";
		
		# get process id
		chomp(my $pid = <$fh>);

		if(kill 10 => $pid) {
			# wait for it to die
			while(1) {
				last unless kill 0 => $pid;
			}
			return 1;
		}
	}

	return 0;
}

#
# set environment
#
sub set_env {
	# create lock file
	open my $fh, '>', "$working_dir/.at_server"
		or die "Couldn't open .at_server: $!";
	# save process id
	print $fh $$, "\n";
}


#
# clean environment
#
sub clean_env {
	# delete lock file
	unlink "$working_dir/.at_server";
	# delete error file
	unlink "$working_dir/.at_err";
	# delete status file
	unlink "$working_dir/.at_status";
}


#
# find_logs
#
sub find_logs {
	my($fileno) = @_;
	my $client = \%{$connections{$fileno}};
	
	return undef unless $client->{logs};
	
	my %files;
	my @paths = @{$client->{logs}};
	
	#
	# replace `hostname` and `domainname` from log paths
	# with actual values or globs
	#
	chomp(my $hostname = `hostname 2>/dev/null`	|| '*');
	chomp(my $domainname = `domainname 2>/dev/null`	|| '*');
	foreach(@paths) {
		s/[`]hostname[`]/$hostname/g;
		s/[`]domainname[`]/$domainname/g;
	}
	
	print_ts("looking for logs...");

	#
	# find all logs that match the filter
	#
	foreach(@paths) {
		foreach(glob) {
			my $path = $_;
			
			# prevent duplicates
			next if $files{$path};
			
			# file or non-existing path
			if(-f $path || !-e $path) {
				$files{$path}=1 if check_filter($client->{filter},$path,$client->{filter_is_exclusive});
			}
			# dir
			elsif(-d $path) {
				# strip trailing slashes
				$path =~ s/(\/)*$//;
				$path .= '/';
				opendir(DIR, $path) or next;
				# FIXME: better ignore rotated logs
				foreach (grep(/(\D|\.80|\.81)$/, readdir(DIR))) {
					my $fpath = $path.$_;
					next unless -f $fpath;
					$files{$fpath}=1 if check_filter($client->{filter},$fpath,$client->{filter_is_exclusive});
				}
				closedir(DIR);
			}
		}
	}
	
	# add new watcher
	print_ts("added to watch pool:") if %files;
	foreach(sort keys %files) {
		print_ts("[+] $_");
		# add new log watcher
		$logpaths{$_}{watchers}{$fileno} = 1;
	}
	
	return sort keys %files;
}


#
# open_log
#
sub open_log {
	my($path) = @_;
	my $fh;
	unless(open $fh, $path) {
		$logpaths{$path}{could_not_open} = 1;
		return undef;
	}
	
	# if could not open last time seek to SOF, else seek to EOF
	my $mode = $logpaths{$path}{could_not_open} ? SEEK_SET : SEEK_END;
	delete $logpaths{$path}{could_not_open};
	
	my $fileno = fileno($fh);
	
	#
	# keep track of new log file
	#
	$logs{$fileno}{fh} = $fh;
	$logs{$fileno}{path} = $path;
	$logpaths{$path}{fileno} = $fileno;
	#fb_set($fileno);
	
	#
	# make unbuffered
	#
	#my $flags = fcntl($fh, F_GETFL, 0);
	#fcntl($fh, F_SETFL, $flags | O_NONBLOCK) if $flags;
	
	# seek to SOF or EOF
	$logs{$fileno}{pos} = sysseek $fh, 0, $mode;
	
	return $fileno;
}


#
# close_log
#
sub close_log {
	my($fileno) = @_;
	
	return unless $fileno;
	
	my $path = $logs{$fileno}{path};
	close $logs{$fileno}{fh};
	#fb_unset($fileno);
	delete $logs{$fileno};
	delete $logpaths{$path}{fileno};
	#delete $logpaths{$path}{watchers};
}


#
# reopen_log
#
sub reopen_log {
	my($fileno) = @_;
	my $path = $logs{$fileno}{path};
	
	print_ts('reopen '.$path);
	
	close_log($fileno);
	
	return undef unless $fileno = open_log($path);

	return $fileno;
}


#
# close_client_logs
#
sub close_client_logs {
	my($fileno) = @_;
	my @closed_logs;
	#
	# remove from log watch list
	#
	foreach(keys %logpaths) {
		delete $logpaths{$_}{watchers}{$fileno};
		# close and remove unwatched logs
		unless(scalar(keys(%{$logpaths{$_}{watchers}}))) {
			close_log($logpaths{$_}{fileno});
			delete $logpaths{$_};
			push @closed_logs, $_;
		}
	}
	
	print_ts("removed from log pool:") if @closed_logs;
	foreach(sort @closed_logs) {
		print_ts('[-] '.$_);
	}
}


#
# check_for_watched_but_unoppened_logs
#
sub check_for_watched_but_unoppened_logs {
	foreach(keys %logpaths) {
		# FIXME: handle mortal log dirs (move dir/file/glob code to separate method)
		open_log($_) if(!$logpaths{$_}{fileno} && scalar(keys(%{$logpaths{$_}{watchers}})));
	}
}


#
# check_for_service_updates
#
sub check_for_service_updates {
	foreach(keys %connections) {
		my $client = \%{$connections{$_}};
		if($client->{got_services}) {
			my $status = service_status(@{$client->{services}});
			if($status ne $client->{service_status}) {
				$client->{service_status} = $status;
				send_service_status($_);
			}
		}
	}
}


#
# send_service_status
#
sub send_service_status {
	my($fileno) = @_;
	
	my $msg =
"Service status:
==============
$connections{$fileno}{service_status}
==============

";
	#send_message($fileno,\$almp{at_msg});
	send_message($fileno,\$msg);
	#send_message($fileno,\$almp{at_end});
}


#
# service_status
#
sub service_status {
	my(@services) = @_;
	my $grep_patt = '';
	
	# build grep pattern
	foreach(@services) {
		$grep_patt .= (length($grep_patt) ? '|' : '') . "$_";
	}
	
	my $cmd = "svcs -a | egrep \'$grep_patt\'";
	
	`$cmd 2>/dev/null`;
}


#
# send_log_list
#
sub send_log_list {
	my($fileno, @logs) = @_;
	
	my $logs_str = '';
	if($logs[0]) {
		$logs_str.="$_\n" foreach(sort @logs);
		chomp($logs_str);
	}
	
	my $msg =
"Watching logs:
==============
$logs_str
==============

";
	
	#send_message($fileno,\$almp{at_msg});
	send_message($fileno,\$msg);
	#send_message($fileno,\$almp{at_end});
}


#
# return 1 if file is allowed
# return 0 if file is denied
#
sub check_filter {
	my ($filter, $path, $exclusive) = @_;
	
	# undefined filter
	return 1 unless $filter;
	
	my $allowed = ($exclusive ? 0 : 1);
	
	foreach(split(/\n+/,$filter)) {
		my @tokens = split /\s+/;
		
		# proc only path filters
		next if scalar(@tokens) >= 2;
		
		print_ts('$tokens[0]='.$tokens[0]);
		
		if($tokens[0] =~ /^!(.*)/ ){
			$allowed = 0 if $path =~ /$1$/;
		}
		else {
			$allowed = 1 if $path =~ /$tokens[0]$/;
		}
	}
	
	my $str = ($allowed ? '[A]' : '[D]');
	print_ts("$str $path");
	
	return $allowed;
}


#
# filter_text
#
sub filter_text {
	my ($filter, $path, $msg) = @_;
	
	my $exclusive = 0;
	my @positive_tokens;
	my @negative_tokens;
	
	foreach(split(/\n+/,$filter)) {
		my @tokens = split /\s+/;
		
		# proc only msg filters
		next if scalar(@tokens) < 2;
		
		if($tokens[0] =~ /^[^!]/) {
			$exclusive = 1;
		}
		else {
			$tokens[0] =~ s/^!//;
		}
		
		if($path =~ /$tokens[0]$/) {
			if($exclusive) {
				push @positive_tokens, $tokens[1];
			}
			else {
				push @negative_tokens, $tokens[1];
			}
		}
	}
	
	if(@positive_tokens && $exclusive) {
		my $regexStr= (join "|", @positive_tokens);

		# filter out everything but the specified string
		$$msg =~ s/^(?!.*($regexStr)).*$//mg;
		$$msg =~ s/^\n+//mg;
	}
	elsif(@negative_tokens) {
		my $regexStr= (join "|", @negative_tokens);
		# filter out the specified string
		$$msg =~ s/^.*($regexStr).*$//mg;
	}
}


#
# preproc_filter
#
sub preproc_filter {
	my($filter) = @_;
	my $res = '';
	foreach(split(/\n+/,$filter)) {
		$res .= convert_string_to_pattern($_) . "\n";
	}
	$res;
}


#
# convert_string_to_pattern
#
sub convert_string_to_pattern {
	my($str) = @_;
	
	# remove existing $
	$str =~ s/\$//g;
	
	# convert globs (save existing .* and convert all single *)
	$str =~ s/\.\*/\$/g;
	$str =~ s/\*/\.\*/g;
	$str =~ s/\$/\.\*/g;
	
	# convert dot (save existing [.] and convert all single dots)
	$str =~ s/\[\.\]/\$/g;
	$str =~ s/\.$/[\.]/g;
	$str =~ s/\[\.\]/\$/g;
	$str =~ s/\.([^*])/[\.]${1}/g;
	$str =~ s/\$/[\.]/g;
	
	return $str;
}


#
# is_exclusive
#
sub is_exclusive {
	my ($filter) = @_;
	
	if($filter) {
		open my($fh), "<", \$filter or return 0;
	
		while(<$fh>) {
			my @tokens = split /\s+/;
		
			# proc only path filters
			next if scalar(@tokens) >= 2;
		
			return 1 if $tokens[0] =~ /^[^!].*/
		}
	}
	return 0;
}


#
# get_time
#
sub get_time {
	strftime "[$$]\t%e_%m_%Y_%H:%M:%S  ", localtime;
}


#
# print_ts
#
sub print_ts {
	my ($msg) = @_;
	print get_time(), "$msg\n";
}


#use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);
#my $flags = fcntl($fh, F_GETFL, 0);
#fcntl($fh, F_SETFL, $flags | O_NONBLOCK) if $flags;
# make unbuffered
#select((select($fh), $|=1)[0]);
