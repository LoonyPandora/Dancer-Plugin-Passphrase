use Test::More import => ['!pass'],  tests => 3;

use strict;
use warnings;

use Dancer::Plugin::Passphrase;

my $secret = "Super Secret Squirrel";

my $default_hash = passphrase($secret)->generate_hash;

like($default_hash, qr/^{CRYPT}\$2a\$04\$/,      'RFC compliant hash generated');
ok(passphrase($secret)->matches($default_hash),  'Match plaintext to hash');
ok(!passphrase('WRONG')->matches($default_hash), 'Incorrect passwords should be rejected');
