use Test::More tests => 1;

use strict;
use warnings;

use Dancer::Plugin::Passphrase;

my $secret = "Super Secret Squirrel";

eval { passphrase($secret)->matches('not an rfc2307 string') };
like $@, qr/An RFC 2307 compliant string must be passed to matches/i, 'Dies on invalid RFC 2307 string';
