use Test::More import => ['!pass'],  tests => 14;

use strict;
use warnings;

use Dancer::Plugin::Passphrase;

my $secret = "Super Secret Squirrel";

for (qw(MD5 SHA-1 SHA-224 SHA-256 SHA-384 SHA-512 BCRYPT)) {
    my $hash = passphrase($secret)->generate_hash({ scheme => $_ });

    ok(passphrase($secret)->matches($hash),  "Match plaintext to hash => $_");
    ok(!passphrase('WRONG')->matches($hash), "Incorrect passwords should be rejected => $_");
}
