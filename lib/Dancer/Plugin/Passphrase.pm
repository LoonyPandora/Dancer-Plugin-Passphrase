package Dancer::Plugin::Passphrase;

# ABSTRACT: Passphrases and Passwords as objects for Dancer

=pod

=head1 NAME

Dancer::Plugin::Passphrase - Passphrases and Passwords as objects for Dancer

=head1 SYNOPSIS

=head1 USAGE

    package MyWebService;
    use Dancer ':syntax';
    use Dancer::Plugin::Passphrase;

    post '/' sub => {
        my $hash = password( param('password') )->generate_hash;
        # [...] Store $hash in DB
    };

    get '/' sub => {
        # [...] Retrieve $stored_hash from the DB

        if ( password( param('password') )->matches($stored_hash) ) {
            # Password matches!
        }
    };

=cut

use strict;

use Dancer::Config;
use Dancer::Plugin;

use Data::Entropy::Algorithms qw(rand_int);
use MIME::Base64 qw(decode_base64 encode_base64);
use Module::Runtime qw(use_module);

our $VERSION = '0.0.1';

register passphrase => \&passphrase;


=head1 KEYWORDS

=head2 passphrase

Pass it a plaintext password, and it returns a Dancer::Plugin::Passphrase 
object that you can generate a hash from, or match against a stored hash

=cut

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

=head1 METHODS

=head2 passphrase->generate_hash

Generates and returns an rfc2307 representation of the plaintext password
that is suitable for storage in a database

    my $hash = passphrase('my password')->generate_hash;

=cut

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



=head2 passphrase->generate_random

Generates and returns 16 cryptographically random
characters from the url-safe base64 charater set

    my $rand_pass = passphrase->generate_random;

The passwords generated are suitable for use as
temporary passwords or one-time authentication tokens.

You can configure the length and the character set
used by passing a hashref of options

    my $rand_pass = passphrase->generate_random({
        length  => 32,
        charset => ['a'..'z', 'A'..'Z'],
    });

=cut

sub generate_random {
    my ($self, $options) = @_;

    # Default is 16 URL-safe base64 chars. Supported everywhere and a reasonable length
    my $length  = $options->{length}  || 16;
    my $charset = $options->{charset} || ['a'..'z', 'A'..'Z', '0'..'9', '-', '_'];

    return join '', map { @$charset[rand_int scalar @$charset] } 1..$length;
}



=head2 passphrase->matches

Matches a plaintext password to a stored hash.
Returns true if the plaintext hashes to the same value as the stored hash.
Returns false if they don't match or if there was an error creating the hash

    passphrase('my password')->matches($stored_hash);

The scalar passed must be a valid rfc2307 or crypt string.

You can pass a hashref of options if you need to provide extra information
about the structure of the hash.

    passphrase('my password')->matches({
        scheme      => '', # RFC 2307 scheme
        hash        => '', # Raw hash
        hash_hex    => '', # Hex version of the hash
        hash_base64 => '', # Base 64 encoded hash
        salt        => '', # Raw salt
        salt_hex    => '', # Hex version of the salt
        salt_base64 => '', # Base 64 encoded salt
    });

=cut

sub matches {
    my ($self, $options) = @_;

    # $options can be scalar containing an rfc2307 string or a crypt string.
    # If not, it should be a hashref of options so we can build an rfc2307 string
    my $hash;
    if (ref($options) eq 'HASH') {
        my $raw_hash = $options->{hash} || pack("H*", $options->{hash_hex}) || decode_base64($options->{hash_base64});
        my $raw_salt = $options->{salt} || pack("H*", $options->{salt_hex}) || decode_base64($options->{salt_base64});
        $hash = '{'.$options->{scheme}.'}'.encode_base64($raw_hash.$raw_salt, '');
    } else {
        $hash = $options;
    }

    # RejectAll, rather than AcceptAll by default. Better to fail secure than fail safe
    $hash = '*' if (!$hash);

    # If it's a crypt string, make it rfc 2307 compliant
    $hash = '{CRYPT}'.$hash if ($hash !~ /^{\w+}/);

    return Authen::Passphrase->from_rfc2307($hash)->match($self->{passphrase});
}



# Returns all information about a generated hash
sub _all_information {
    my ($self) = @_;

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



# Adds a random salt by default, unless you specify otherwise
sub _add_salt {
    my ($config) = @_;

    # Amount of salt in bytes. It should be as long as the final hash function
    my $salt_length = {
        'SHA-512' => 64,
        'SHA-384' => 48,
        'SHA-256' => 32,
        'SHA-224' => 28,
        'SHA-1'   => 20,
        'MD5'     => 16,
        'MD4'     => 16,
    };

    unless ( grep /^salt/, keys %{$config} ) {
        $config->{salt_random} = $salt_length->{ $config->{algorithm} };
    }

    return $config;
}



register_plugin;

1;



=head1 DESCRIPTION

L<http://codahale.com/how-to-safely-store-a-password/>

=head1 CONFIGURATION

=head1 SEE ALSO

L<Dancer>, L<Authen::Passphrase>

=head1 COOKBOOK

=head1 AUTHOR

James Aitken <jaitken@cpan.org>

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2011 by James Aitken.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut

