#!/usr/bin/perl
#
# Helper of test04.lua: runs RC4 jobs with Perl modules. Usage:
#
#   perl test04.pl <backend> <jobfile>
#
#   backend  rc4     Crypt::RC4
#            cryptx  Crypt::Stream::RC4 of CryptX (keys of 5 to 256 bytes)
#
# The job file and the output are those of test04.py: one job per line, "key drop data"
# (hex, "-" for empty data), one result line per job: the output in hex ("-" if empty),
# "ERR" or "SKIP"; "UNAVAILABLE" if the module is not installed.

use strict;
use warnings;

my ($backend, $jobfile) = @ARGV;

my $run;
my $SKIP = \'skip';   # the result of a job that the backend does not support

if ($backend eq 'rc4') {
    unless (eval { require Crypt::RC4; 1 }) {
        print "UNAVAILABLE\n";
        exit 0;
    }
    $run = sub {
        my ($key, $drop, $data) = @_;
        my $c = Crypt::RC4->new($key);
        $c->RC4("\0" x $drop) if $drop > 0;
        return $c->RC4($data);
    };
} elsif ($backend eq 'cryptx') {
    unless (eval { require Crypt::Stream::RC4; 1 }) {
        print "UNAVAILABLE\n";
        exit 0;
    }
    $run = sub {
        my ($key, $drop, $data) = @_;
        return $SKIP if length($key) < 5;
        my $c = Crypt::Stream::RC4->new($key);
        $c->crypt("\0" x $drop) if $drop > 0;
        return $c->crypt($data);
    };
} else {
    die "unknown backend $backend\n";
}

open(my $f, '<', $jobfile) or die "cannot open $jobfile: $!";
while (my $line = <$f>) {
    my @fields = split(' ', $line);
    next unless @fields;
    my ($key, $drop, $data) = @fields;
    my $r = eval { $run->(pack('H*', $key), $drop, $data eq '-' ? '' : pack('H*', $data)) };
    if (!defined $r) {
        print "ERR\n";
    } elsif (ref($r) && $r == $SKIP) {
        print "SKIP\n";
    } else {
        print length($r) ? unpack('H*', $r) : '-', "\n";
    }
}
close($f);
