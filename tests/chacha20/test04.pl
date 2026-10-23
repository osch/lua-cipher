#!/usr/bin/perl
#
# Helper of test04.lua: runs ChaCha20, ChaCha20-Poly1305 and Poly1305 jobs with the Perl
# modules of CryptX. Usage:
#
#   perl test04.pl cryptx <jobfile>
#
#   Crypt::Stream::ChaCha (8 and 12 byte nonces), Crypt::Stream::XChaCha (24 byte
#   nonces, CryptX 0.089 and later, without a counter: only counters up to 1000, by
#   discarding the keystream before), Crypt::AuthEnc::ChaCha20Poly1305 (24 byte nonces
#   if the version supports them) and Crypt::Mac::Poly1305
#
# The job file and the output are those of test04.py: one job per line,
# "op key iv counter aad tag data" (hex, "-" for empty), one result line per job:
# "<output> <tag>", "ERR" or "SKIP"; "UNAVAILABLE" if the modules are not installed.

use strict;
use warnings;

my ($backend, $jobfile) = @ARGV;

sub unhex { my ($s) = @_; return $s eq '-' ? '' : pack('H*', $s); }
sub tohex { my ($b) = @_; return length($b) ? unpack('H*', $b) : '-'; }

my $SKIP = \'skip';   # the result of a job that the backend does not support

die "unknown backend $backend\n" unless $backend eq 'cryptx';
unless (eval { require Crypt::Stream::ChaCha; require Crypt::AuthEnc::ChaCha20Poly1305;
               require Crypt::Mac::Poly1305; 1 }) {
    print "UNAVAILABLE\n";
    exit 0;
}
my $hasXChaCha = eval { require Crypt::Stream::XChaCha; 1 };
# XChaCha20-Poly1305 (24 byte nonces) needs a newer CryptX
my $hasXAead = eval {
    my @r = Crypt::AuthEnc::ChaCha20Poly1305::chacha20poly1305_encrypt_authenticate("\0" x 32, "\0" x 24, '', 'x');
    1;
};

my $run = sub {
    my ($op, $key, $iv, $counter, $aad, $tag, $data) = @_;
    if ($op eq 'crypt') {
        if (length($iv) == 24) {
            return ($SKIP) if !$hasXChaCha || $counter > 1000;
            my $c = Crypt::Stream::XChaCha->new($key, $iv);
            $c->crypt("\0" x (64 * $counter)) if $counter > 0;
            return ($c->crypt($data), '');
        }
        return (Crypt::Stream::ChaCha->new($key, $iv, $counter, 20)->crypt($data), '');
    }
    if ($op eq 'poly') {
        return (Crypt::Mac::Poly1305::poly1305($key, $data), '');
    }
    return ($SKIP) if length($iv) == 24 && !$hasXAead;
    if ($op eq 'enc') {
        my ($ct, $t) = Crypt::AuthEnc::ChaCha20Poly1305::chacha20poly1305_encrypt_authenticate($key, $iv, $aad, $data);
        return ($ct, $t);
    }
    my $pt = Crypt::AuthEnc::ChaCha20Poly1305::chacha20poly1305_decrypt_verify($key, $iv, $aad, $data, $tag);
    die "authentication failed" unless defined $pt;
    return ($pt, '');
};

open(my $f, '<', $jobfile) or die "cannot open $jobfile: $!";
while (my $line = <$f>) {
    my @fields = split(' ', $line);
    next unless @fields;
    my ($op, $key, $iv, $counter, $aad, $tag, $data) = @fields;
    my @r = eval { $run->($op, unhex($key), unhex($iv), $counter, unhex($aad), unhex($tag), unhex($data)) };
    if (!@r) {
        print "ERR\n";
    } elsif (ref($r[0]) && $r[0] == $SKIP) {
        print "SKIP\n";
    } else {
        print tohex($r[0]), ' ', tohex($r[1]), "\n";
    }
}
close($f);
