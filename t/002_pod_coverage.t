use Test::More;

use strict;
use warnings;

eval "use Test::Pod::Coverage";
plan skip_all => "Test::Pod::Coverage required for testing pod coverage" if $@;

plan tests => 1;

pod_coverage_ok(
    "Dancer::Plugin::Passphrase",
    { trustme => [qr/^(as_rfc2307|generate_hash)$/] },  # Aliases for 'rfc2307', and 'generate'
    "Dancer::Plugin::Passphrase has full POD coverage"
);
