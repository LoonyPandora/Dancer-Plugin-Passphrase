use Test::More tests => 4;

use strict;
use warnings;

use Dancer qw(:tests);
use Dancer::Plugin::Passphrase;
use Encode;

# Unicode Character 'PILE OF POO'.
my $secret      = "\x{1F4A9}";
my $utf8_secret = Encode::encode_utf8("\x{1F4A9}"); 

my $sha_rfc2307    = passphrase($secret)->generate({ algorithm => 'SHA-1' })->rfc2307;
my $md5_rfc2307    = passphrase($utf8_secret)->generate({ algorithm => 'MD5' })->rfc2307;
my $bcrypt_rfc2307 = passphrase($utf8_secret)->generate->rfc2307;

ok(passphrase($utf8_secret)->matches($md5_rfc2307),    'UTF8 Match for MD5');
ok(passphrase($utf8_secret)->matches($bcrypt_rfc2307), 'UTF8 Match for bcrypt');

ok(passphrase($secret)->matches($sha_rfc2307),         'Raw match for SHA');
ok(passphrase($utf8_secret)->matches($sha_rfc2307),    'UTF8 match for SHA');
