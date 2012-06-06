use Test::More tests => 12;

use strict;
use warnings;

use Dancer qw(:tests);
use Dancer::Plugin::Passphrase;
use Encode;

# Unicode Character 'PILE OF POO'.
my $secret      = "\x{1F4A9}";
my $utf8_secret = Encode::encode_utf8("\x{1F4A9}"); 


# SHA Tests
my $sha_raw  = passphrase($secret)->generate({ algorithm => 'SHA-1' })->rfc2307;
my $sha_utf8 = passphrase($utf8_secret)->generate({ algorithm => 'SHA-1' })->rfc2307;

ok(passphrase($secret)->matches($sha_raw),        'Raw matches Raw for SHA');
ok(passphrase($secret)->matches($sha_utf8),       'Raw matches UTF8 for SHA');
ok(passphrase($utf8_secret)->matches($sha_utf8),  'UTF8 matches UTF8 for SHA');
ok(passphrase($utf8_secret)->matches($sha_raw),   'UTF8 matches Raw for SHA');



# PBKDF2 Tests
my $pbkdf2_raw  = passphrase($secret)->generate({ algorithm => 'PBKDF2' })->rfc2307;
my $pbkdf2_utf8 = passphrase($utf8_secret)->generate({ algorithm => 'PBKDF2' })->rfc2307;

ok(passphrase($secret)->matches($pbkdf2_raw),        'Raw matches Raw for PBKDF2');
ok(passphrase($secret)->matches($pbkdf2_utf8),       'Raw matches UTF8 for PBKDF2');
ok(passphrase($utf8_secret)->matches($pbkdf2_utf8),  'UTF8 matches UTF8 for PBKDF2');
ok(passphrase($utf8_secret)->matches($pbkdf2_raw),   'UTF8 matches Raw for PBKDF2');



# MD5 Tests
my $md5_utf8 = passphrase($utf8_secret)->generate({ algorithm => 'MD5' })->rfc2307;

ok(passphrase($utf8_secret)->matches($md5_utf8),  'UTF8 matches UTF8 for MD5');
eval { passphrase($secret)->generate({ algorithm => 'MD5' })->rfc2307; };
like $@, qr/Wide character in subroutine entry/i, 'MD5 needs encoded text';



# Bcrypt Tests
my $bcrypt_utf8 = passphrase($utf8_secret)->generate({ algorithm => 'Bcrypt' })->rfc2307;

ok(passphrase($utf8_secret)->matches($bcrypt_utf8),  'UTF8 matches UTF8 for Bcrypy');
eval { passphrase($secret)->generate({ algorithm => 'Bcrypt' })->rfc2307; };
like $@, qr/input must contain only octets/i, 'Bcrypt needs encoded text';
