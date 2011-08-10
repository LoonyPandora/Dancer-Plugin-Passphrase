package Dancer::Plugin::Passphrase;

# ABSTRACT: Passphrases and Passwords as objects for Dancer

use strict;

use Dancer::Plugin;
use Dancer::Config;
use Module::Runtime qw/use_module/;
use MIME::Base64 qw/encode_base64/;

our $VERSION = '0.0.1';


register password => \&password;


sub password {
    my $plaintext = shift;
    my $config    = plugin_setting;

   # Default settings if nothing in config.yml or we've not configured the default
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

    # Return a bunch of useful info if we want.
    # Cleaner than lots of methods.
    if (wantarray) {

    }

    return $self->_extended_rfc2307();
}


# Returns true if password matches, empty string if not
sub matches {
    my ($self, $options) = @_;

    # $options should be rfc2307 string, crypt string, 
    # or a hashref of options needed to construct an rfc2307 string.
    my $hash;
    if (ref($options) eq 'HASH') {
        my $hash = $options->{hash} || pack("H*", $options->{hash_hex});
        $hash = '{'.$options->{scheme}.'}'.encode_base64($hash.$options->{salt}, '');
    } else {
        $hash = $options;
    }

    # If it's a crypt string, make it an rfc 2307 crypt
    $hash = '{CRYPT}'.$hash if ($hash !~ /^{\w+}/);

    return Authen::Passphrase->from_rfc2307($hash)->match($self->{passphrase});
}


# unofficial extensions to the rfc that are widely supported
sub _extended_rfc2307 {
    my ($self) = @_;

    my $scheme = $self->{recogniser}->{algorithm};
    $scheme =~ s/-//;

    if ($self->{recogniser}->{algorithm} ~~ [qw(SHA-224 SHA-256 SHA-384 SHA-512)]) {
        return "{".($self->{recogniser}->{salt} eq "" ? "" : "S").$scheme."}".
            encode_base64($self->{recogniser}->{hash}.$self->{recogniser}->{salt}, '');
    }

    return $self->{recogniser}->as_rfc2307();
}


sub _add_salt {
    my ($config) = @_;

    my $salt_length = {
        'SHA-512' => 64,
        'SHA-384' => 48,
        'SHA-256' => 32,
        'SHA-224' => 28,
        'SHA-1'   => 20,
        'MD5'     => 16,
        'MD4'     => 16,
    };

    # Get a random salt, unless one has been explicitly set
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

This module gives secure generation and storage of passwords. It makes it hard to generate code that is not secure.
It provdides an easy upgrade path to other modules, and stores passwords in as standard a format as possible.

It strives to be a drop in replacement for older code, so one can use this plugin with leagacy applications,
then flick the switch to a more secure method. i.e passwords are currently stored as unsalted md5 - this module can work with that.
New code you write from then on can store passwords as bcrypt, while still verifying against the old passwords.
When user logs in you can upgrade the old passwords


