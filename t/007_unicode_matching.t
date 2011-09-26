use Test::More import => ['!pass'],  tests => 4;

use strict;
use warnings;

use Dancer::Plugin::Passphrase;
use Encode;

# Unicode Character 'PILE OF POO'.
my $secret      = "\x{1F4A9}";
my $utf8_secret = Encode::encode_utf8("\x{1F4A9}"); 

my $sha_hash    = passphrase($secret)->generate_hash({ scheme => 'SHA-1' });
my $md5_hash    = passphrase($utf8_secret)->generate_hash({ scheme => 'MD5' });
my $bcrypt_hash = passphrase($utf8_secret)->generate_hash;

ok(passphrase($utf8_secret)->matches($md5_hash),    'UTF8 Match for MD5');
ok(passphrase($utf8_secret)->matches($bcrypt_hash), 'UTF8 Match for bcrypt');

ok(passphrase($secret)->matches($sha_hash),         'Raw match for SHA');
ok(passphrase($utf8_secret)->matches($sha_hash),    'UTF8 match for SHA');
