use Test::More import => ['!pass'],  tests => 11;

use strict;
use warnings;

use Dancer::Plugin::Passphrase;

my $secret = "Super Secret Squirrel";

my $object = passphrase($secret)->generate;

ok(ref($object) eq 'Dancer::Plugin::Passphrase',  'Creates correct object');
ok($object->rfc2307,                              'Contains RFC 2307 representation');
ok($object->algorithm  eq 'Bcrypt',               'Contains correct scheme');
ok($object->cost       eq '04',                   'Contains correct cost');
ok($object->raw_hash,                             'Contains raw salt');
ok($object->hash_hex,                             'Contains hex hash');
ok($object->hash_base64,                          'Contains base64 hash');
ok($object->raw_salt,                             'Contains raw salt');
ok($object->salt_hex,                             'Contains hex salt');
ok($object->salt_base64,                          'Contains base64 salt');
ok($object->plaintext eq $secret,                 'Contains correct plaintext');
