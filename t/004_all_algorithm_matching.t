use Test::More import => ['!pass'],  tests => 14;

use strict;
use warnings;

use Dancer::Plugin::Passphrase;

my $secret = "Super Secret Squirrel";

for (qw(MD5 SHA-1 SHA-224 SHA-256 SHA-384 SHA-512 BCRYPT)) {
    my $rfc2307 = passphrase($secret)->generate({ scheme => $_ });

    ok(passphrase($secret)->matches($rfc2307),  "Match plaintext to hash => $_");
    ok(!passphrase('WRONG')->matches($rfc2307), "Incorrect passwords should be rejected => $_");
}
