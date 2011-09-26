use Test::More import => ['!pass'],  tests => 3;

use strict;
use warnings;

use Dancer::Plugin::Passphrase;

my $secret = "Super Secret Squirrel";

my $default_hash = passphrase($secret)->generate_hash();
my $custom_hash  = passphrase($secret)->generate_hash({
    package => 'BlowfishCrypt',
    cost    => 8
});


# Generates hash with default settings
like($default_hash, qr/^{CRYPT}\$2a\$04\$/, 'Generate hash with default settings');

# Generate hash with custom work factor
like($custom_hash, qr/^{CRYPT}\$2a\$08\$/, 'Generate hash with custom work factor');

# Check that matches to plaintext
ok(passphrase($secret)->matches($default_hash), 'Match plaintext to hash');

# Check that fails if password doesn't match
#ok(passphrase('Wrong Secret')->matches($default_hash), 'Match plaintext to hash');



#ok(passphrase($secret)->generate_hash(), 'Generate hash with custom settings');

#ok(passphrase($secret)->matches($stored_hash), 'Match plaintext to hash');

