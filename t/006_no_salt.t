use Test::More import => ['!pass'],  tests => 2;

use strict;
use warnings;

use Dancer::Plugin::Passphrase;

my $secret     = "Super Secret Squirrel";
my $known_value = '{SHA}lmrkJArUS4AvuHtllhJG2hOBlcE=';

# Bcrypt has to have a salt, so we pick a different algorithm
my $hash = passphrase($secret)->generate_hash({ scheme => 'SHA-1', salt => '' });

ok(passphrase($secret)->matches($known_value),  "Match plaintext to it's pre-computed hash");
ok(passphrase($secret)->matches($hash),         "Match plaintext to it's generated hash");
