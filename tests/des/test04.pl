#!/usr/bin/perl
#
# Helper of test04.lua: runs DES and Triple DES jobs with Perl modules. Usage:
#
#   perl test04.pl <backend> <jobfile>
#
#   backend  cryptx  CryptX: Crypt::Mode::ECB, ::CBC, ::CFB, ::OFB, ::CTR with the ciphers
#                    DES (8 byte keys) and DES_EDE (24 byte keys, and 16 byte keys if
#                    the version supports them; no cfb8)
#            des     Crypt::DES (8 byte keys) and Crypt::DES_EDE3 (24 byte keys): the
#                    block functions, ecb without padding
#            cbc     Crypt::CBC with Crypt::DES and Crypt::DES_EDE3 (cbc, with -header
#                    'none' and the key used as it is)
#
# The job file and the output are those of test04.py: one job per line,
# "op mode key iv padding data" (hex, "-" for empty), one result line per job: the output
# in hex ("-" if empty), "ERR" or "SKIP"; "UNAVAILABLE" if the modules are not installed.

use strict;
use warnings;

my ($backend, $jobfile) = @ARGV;

sub unhex { my ($s) = @_; return $s eq '-' ? '' : pack('H*', $s); }
sub tohex { my ($b) = @_; return length($b) ? unpack('H*', $b) : '-'; }

my $run;
my $SKIP = \'skip';   # the result of a job that the backend does not support

if ($backend eq 'cryptx') {
    unless (eval { require Crypt::Mode::ECB; require Crypt::Mode::CBC; require Crypt::Mode::CFB;
                   require Crypt::Mode::OFB; require Crypt::Mode::CTR; 1 }) {
        print "UNAVAILABLE\n";
        exit 0;
    }
    # two key Triple DES (16 byte keys) needs a newer libtomcrypt
    my $has2key = eval { Crypt::Mode::ECB->new('DES_EDE', 0)->encrypt("\0" x 8, "\1" x 16); 1 };
    $run = sub {
        my ($op, $mode, $key, $iv, $pad, $data) = @_;
        return $SKIP if length($key) == 16 && !$has2key;
        my $padding = ($pad eq 'pkcs7') ? 1 : 0;
        my $cipher = (length($key) == 8) ? 'DES' : 'DES_EDE';
        my $m;
        if    ($mode eq 'ecb') { $m = Crypt::Mode::ECB->new($cipher, $padding); }
        elsif ($mode eq 'cbc') { $m = Crypt::Mode::CBC->new($cipher, $padding); }
        elsif ($mode eq 'cfb') { $m = Crypt::Mode::CFB->new($cipher); }
        elsif ($mode eq 'ofb') { $m = Crypt::Mode::OFB->new($cipher); }
        elsif ($mode eq 'ctr') { $m = Crypt::Mode::CTR->new($cipher, 1, 8); }   # big endian, 64 bit
        else { return $SKIP; }
        my @args = ($mode eq 'ecb') ? ($data, $key) : ($data, $key, $iv);
        return $op eq 'enc' ? $m->encrypt(@args) : $m->decrypt(@args);
    };
} elsif ($backend eq 'des') {
    unless (eval { require Crypt::DES; require Crypt::DES_EDE3; 1 }) {
        print "UNAVAILABLE\n";
        exit 0;
    }
    $run = sub {
        my ($op, $mode, $key, $iv, $pad, $data) = @_;
        return $SKIP if $mode ne 'ecb' || $pad ne 'none' || length($key) == 16;
        my $c = (length($key) == 8) ? Crypt::DES->new($key) : Crypt::DES_EDE3->new($key);
        my $out = '';
        for (my $i = 0; $i < length($data); $i += 8) {
            my $b = substr($data, $i, 8);
            $out .= $op eq 'enc' ? $c->encrypt($b) : $c->decrypt($b);
        }
        return $out;
    };
} elsif ($backend eq 'cbc') {
    unless (eval { require Crypt::CBC; require Crypt::DES; require Crypt::DES_EDE3; 1 }) {
        print "UNAVAILABLE\n";
        exit 0;
    }
    $run = sub {
        my ($op, $mode, $key, $iv, $pad, $data) = @_;
        return $SKIP if $mode ne 'cbc' || length($key) == 16;
        # Crypt::CBC decrypts empty data without padding to a block of garbage
        return $SKIP if $op eq 'dec' && $pad eq 'none' && length($data) == 0;
        my %args = (-cipher => (length($key) == 8) ? 'Crypt::DES' : 'Crypt::DES_EDE3', -key => $key,
                    -keysize => length($key), -iv => $iv, -header => 'none',
                    -padding => ($pad eq 'pkcs7') ? 'standard' : 'none');
        # the key used as it is: -pbkdf 'none' since Crypt::CBC 3, before -literal_key
        if ($Crypt::CBC::VERSION >= 3) { $args{-pbkdf} = 'none'; } else { $args{-literal_key} = 1; }
        my $c = Crypt::CBC->new(%args);
        return $op eq 'enc' ? $c->encrypt($data) : $c->decrypt($data);
    };
} else {
    die "unknown backend $backend\n";
}

open(my $f, '<', $jobfile) or die "cannot open $jobfile: $!";
while (my $line = <$f>) {
    my @fields = split(' ', $line);
    next unless @fields;
    my ($op, $mode, $key, $iv, $pad, $data) = @fields;
    my @r = eval { $run->($op, $mode, unhex($key), unhex($iv), $pad, unhex($data)) };
    if (!@r) {
        print "ERR\n";
    } elsif (ref($r[0]) && $r[0] == $SKIP) {
        print "SKIP\n";
    } else {
        print tohex($r[0]), "\n";
    }
}
close($f);
