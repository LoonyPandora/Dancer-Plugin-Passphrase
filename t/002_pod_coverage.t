use Test::More;

use strict;
use warnings;

eval "use Test::Pod::Coverage 1.08";
plan skip_all => "Test::Pod::Coverage 1.08 required for testing POD coverage" if $@;

plan tests => 1;

pod_coverage_ok(
    "Dancer::Plugin::Passphrase",
    { trustme => [qr/^(as_rfc2307|generate_hash)$/] },  # Deprecated Aliases for 'rfc2307', and 'generate'
    "Dancer::Plugin::Passphrase has full POD coverage"
);
