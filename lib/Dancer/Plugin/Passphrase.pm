package Dancer::Plugin::Passphrase;

# ABSTRACT: Passphrases and Passwords as objects for Dancer

use strict;

use Dancer::Plugin;
use Dancer::Config;
use Module::Runtime qw/use_module/;
use MIME::Base64 qw/decode_base64 encode_base64/;
use Data::Entropy::Algorithms qw/rand_int/;
use Data::Dumper;

our $VERSION = '0.0.1';

register passphrase => \&passphrase;


sub passphrase {
    my ($plaintext) = @_;
    my $config    = plugin_setting;

   # Default settings if nothing in config.yml
    if (!defined($config->{default}) || !defined($config->{$config->{default}})) {
        $config->{default} = 'BlowfishCrypt';
        $config->{BlowfishCrypt} = {
            cost        => 4,
            key_nul     => 1,
            salt_random => 128,
        };
    }

    my $package = $config->{default};
    $config->{$package} = _add_salt($config->{$package});

    return bless {
        package    => $package,
        config     => $config->{$package},
        passphrase => $plaintext,
    }, 'Dancer::Plugin::Passphrase';

}


sub generate_hash {
    my ($self, $options) = @_;

    my $config  = $options || $self->{config};
    my $package = $options->{package} || $self->{package};

    delete $config->{package};
    $config = _add_salt($config);

    $self->{recogniser} = use_module("Authen::Passphrase::$package")->new(
         %{$config}, (passphrase => $self->{passphrase})
    );

    # Return a bunch of useful info if we ask for it. Cleaner than lots of methods.
    if (wantarray) {
        return $self->_all_information;
    }

    return $self->_extended_rfc2307;
}


# Just a wrapper for random string that allows you to pass options
sub generate_random {
    my ($self, $options) = @_;

    # Default is 16 URL-safe base64 chars. Supported everywhere and a reasonable length
    my $length  = $options->{length}  || 16;
    my $charset = $options->{charset} || ['a'..'z', 'A'..'Z', '0'..'9', '-', '_'];

    return join '', map { @$charset[rand_int scalar @$charset] } 1..$length;
}


# Returns true if passphrase matches, empty string if not
sub matches {
    my ($self, $options) = @_;

    # $options can be scalar containing an rfc2307 string or a crypt string.
    # If not, it should be a hashref of options so we can build an rfc2307 string
    my $hash;
    if (ref($options) eq 'HASH') {
        my $raw_hash = $options->{hash} || pack("H*", $options->{hash_hex}) || decode_base64($options->{hash_base64});
        $hash = '{'.$options->{scheme}.'}'.encode_base64($raw_hash.$options->{salt}, '');
    } else {
        $hash = $options;
    }

    # RejectAll, rather than AcceptAll by default. Better to fail secure than fail safe
    $hash = '*' if (!$hash);

    # If it's a crypt string, make it rfc 2307 compliant
    $hash = '{CRYPT}'.$hash if ($hash !~ /^{\w+}/);

    return Authen::Passphrase->from_rfc2307($hash)->match($self->{passphrase});
}


# Checks and returns a hash of information about the just generated hash
sub _all_information {
    my ($self, $package) = @_;

    my @potential = qw(
        salt
        salt_hex
        salt_base64
        hash
        hash_hex
        hash_base64
        cost
        key_nul
        as_crypt
        algorithm
    );

    my %defined;
    for my $method (@potential) {
        if ($self->{recogniser}->can($method)) {
            $defined{$method} = $self->{recogniser}->$method;
        }
    }

    return %defined;
}


# Unofficial extensions to the rfc that are widely supported
sub _extended_rfc2307 {
    my ($self) = @_;

    my $r = $self->{recogniser};
    my $scheme = $r->{algorithm};
    $scheme =~ s/-//;

    if ($r->{algorithm} ~~ [qw(SHA-224 SHA-256 SHA-384 SHA-512)]) {
        # Check for salt and add the S prefix if it has.
        return "{".($r->{salt} eq "" ? "" : "S").$scheme."}".
            encode_base64($r->{hash}.$r->{salt}, '');
    }

    return $r->as_rfc2307();
}


sub _add_salt {
    my ($config) = @_;

    # Amount of salt in bytes. It should be as long as the final hash function.
    my $salt_length = {
        'SHA-512' => 64,
        'SHA-384' => 48,
        'SHA-256' => 32,
        'SHA-224' => 28,
        'SHA-1'   => 20,
        'MD5'     => 16,
        'MD4'     => 16,
    };

    # Specify salt of necessary length - unless we've manually specified it.
    unless ( grep /^salt/, keys %{$config} ) {
        $config->{salt_random} = $salt_length->{ $config->{algorithm} };
    }

    return $config;
}


register_plugin;

1;


=cut=


Aim is to enable developers to stop worrying about these solved problems, and move on to the rest of their app.

Few devs are crypto experts and will either waste a lot of time figuring out how to make things secure, or will end up with a system
that SEEMS secure to them, but in actual fact is not secure.

This module gives secure generation and storage of passphrases. It makes it hard to generate code that is not secure.
It provdides an easy upgrade path to other modules, and stores passphrases in as standard a format as possible.

It strives to be a drop in replacement for older code, so one can use this plugin with leagacy applications,
then flick the switch to a more secure method. i.e passphrases are currently stored as unsalted md5 - this module can work with that.
New code you write from then on can store passphrases as bcrypt, while still verifying against the old passphrases.
When user logs in you can upgrade the old passphrases


