use Test::More;

use strict;
use warnings;

eval "use Test::Pod::Coverage 1.08";
plan skip_all => "Test::Pod::Coverage 1.08 required for testing POD coverage" if $@;

plan tests => 1;

pod_coverage_ok("Dancer::Plugin::Passphrase", "Dancer::Plugin::Passphrase has full POD coverage");
