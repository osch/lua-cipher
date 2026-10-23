#!/usr/bin/perl
#
# Helper of test04.lua: runs AES jobs with Perl modules. Usage:
#
#   perl test04.pl <backend> <jobfile>
#
#   backend  cryptx    CryptX: Crypt::Mode::ECB, ::CBC, ::CFB, ::OFB, ::CTR and
#                      Crypt::AuthEnc::GCM (no cfb8)
#            rijndael  Crypt::Rijndael with its modes ECB, CBC, CFB, OFB, CTR (whole
#                      blocks only, no padding, no cfb8, no gcm)
#            cbc       Crypt::CBC with Crypt::Rijndael (cbc, with -header 'none' and the
#                      key used as it is)
#
# The job file and the output are those of test04.py: one job per line,
# "op mode key iv padding aad tag data" (hex, "-" for empty), one result line per job:
# "<output> <tag>", "ERR" or "SKIP"; "UNAVAILABLE" if the modules are not installed.

use strict;
use warnings;

my ($backend, $jobfile) = @ARGV;

sub unhex { my ($s) = @_; return $s eq '-' ? '' : pack('H*', $s); }
sub tohex { my ($b) = @_; return length($b) ? unpack('H*', $b) : '-'; }

my $run;
my $SKIP = \'skip';   # the result of a job that the backend does not support

if ($backend eq 'cryptx') {
    unless (eval { require Crypt::Mode::ECB; require Crypt::Mode::CBC; require Crypt::Mode::CFB;
                   require Crypt::Mode::OFB; require Crypt::Mode::CTR; require Crypt::AuthEnc::GCM; 1 }) {
        print "UNAVAILABLE\n";
        exit 0;
    }
    $run = sub {
        my ($op, $mode, $key, $iv, $pad, $aad, $tag, $data) = @_;
        my $padding = ($pad eq 'pkcs7') ? 1 : 0;
        my $m;
        if ($mode eq 'gcm') {
            if ($op eq 'enc') {
                my ($ct, $t) = Crypt::AuthEnc::GCM::gcm_encrypt_authenticate('AES', $key, $iv, $aad, $data);
                return ($ct, substr($t, 0, $tag));
            }
            return ($SKIP) if length($tag) != 16;
            my $pt = Crypt::AuthEnc::GCM::gcm_decrypt_verify('AES', $key, $iv, $aad, $data, $tag);
            die "authentication failed" unless defined $pt;
            return ($pt, '');
        }
        if    ($mode eq 'ecb') { $m = Crypt::Mode::ECB->new('AES', $padding); }
        elsif ($mode eq 'cbc') { $m = Crypt::Mode::CBC->new('AES', $padding); }
        elsif ($mode eq 'cfb') { $m = Crypt::Mode::CFB->new('AES'); }
        elsif ($mode eq 'ofb') { $m = Crypt::Mode::OFB->new('AES'); }
        elsif ($mode eq 'ctr') { $m = Crypt::Mode::CTR->new('AES', 1, 16); }   # big endian, 128 bit
        else { return ($SKIP); }
        my @args = ($mode eq 'ecb') ? ($data, $key) : ($data, $key, $iv);
        return ($op eq 'enc' ? $m->encrypt(@args) : $m->decrypt(@args), '');
    };
} elsif ($backend eq 'rijndael') {
    unless (eval { require Crypt::Rijndael; 1 }) {
        print "UNAVAILABLE\n";
        exit 0;
    }
    my %modes = (ecb => 'MODE_ECB', cbc => 'MODE_CBC', cfb => 'MODE_CFB', ofb => 'MODE_OFB',
                 ctr => 'MODE_CTR');
    $run = sub {
        my ($op, $mode, $key, $iv, $pad, $aad, $tag, $data) = @_;
        return ($SKIP) if !$modes{$mode} || $pad ne 'none' || length($data) % 16;
        my $c = Crypt::Rijndael->new($key, Crypt::Rijndael->can($modes{$mode})->());
        $c->set_iv($iv) if $mode ne 'ecb';
        return ($op eq 'enc' ? $c->encrypt($data) : $c->decrypt($data), '');
    };
} elsif ($backend eq 'cbc') {
    unless (eval { require Crypt::CBC; require Crypt::Rijndael; 1 }) {
        print "UNAVAILABLE\n";
        exit 0;
    }
    $run = sub {
        my ($op, $mode, $key, $iv, $pad, $aad, $tag, $data) = @_;
        return ($SKIP) if $mode ne 'cbc';
        # Crypt::CBC decrypts empty data without padding to a block of garbage
        return ($SKIP) if $op eq 'dec' && $pad eq 'none' && length($data) == 0;
        my %args = (-cipher => 'Crypt::Rijndael', -key => $key, -keysize => length($key),
                    -iv => $iv, -header => 'none', -padding => ($pad eq 'pkcs7') ? 'standard' : 'none');
        # the key used as it is: -pbkdf 'none' since Crypt::CBC 3, before -literal_key
        if ($Crypt::CBC::VERSION >= 3) { $args{-pbkdf} = 'none'; } else { $args{-literal_key} = 1; }
        my $c = Crypt::CBC->new(%args);
        return ($op eq 'enc' ? $c->encrypt($data) : $c->decrypt($data), '');
    };
} else {
    die "unknown backend $backend\n";
}

open(my $f, '<', $jobfile) or die "cannot open $jobfile: $!";
while (my $line = <$f>) {
    my @fields = split(' ', $line);
    next unless @fields;
    my ($op, $mode, $key, $iv, $pad, $aad, $tag, $data) = @fields;
    my @r = eval { $run->($op, $mode, unhex($key), unhex($iv), $pad, unhex($aad),
                          $op eq 'enc' ? $tag : unhex($tag), unhex($data)) };
    if (!@r) {
        print "ERR\n";
    } elsif (ref($r[0]) && $r[0] == $SKIP) {
        print "SKIP\n";
    } else {
        print tohex($r[0]), ' ', tohex($r[1]), "\n";
    }
}
close($f);
