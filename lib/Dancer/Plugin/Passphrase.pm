package Dancer::Plugin::Passphrase;

# ABSTRACT: Passphrases and Passwords as objects for Dancer

=head1 NAME

Dancer::Plugin::Passphrase - Passphrases and Passwords as objects for Dancer

=head1 SYNOPSIS

This plugin manages the hasing of passwords for Dancer apps, allowing 
developers to follow best cryptography practice without having to 
become a cryptography expert.

It wraps the functionality of L<Authen::Passphrase>, providing sane defaults.

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

    get '/generate_password' sub => {
        return password->generate_random;
    };

=cut

use strict;

use Dancer::Plugin;

use Authen::Passphrase;
use Data::Entropy::Algorithms qw(rand_int);
use MIME::Base64 qw(decode_base64 encode_base64);
use Module::Runtime qw(use_module);

use Data::Dumper;

our $VERSION = '0.0.1';

register passphrase => \&passphrase;


=head1 KEYWORDS

=head2 passphrase

Given a plaintext password, it returns a Dancer::Plugin::Passphrase 
object that you can generate a new hash from, or match against a stored hash.

=cut

sub passphrase {
    my $plaintext = shift;
    my $config    = plugin_setting;

    # Default settings if nothing configured
    if (!defined($config->{default}) || !defined($config->{$config->{default}})) {
        $config->{default} = 'BlowfishCrypt';
        $config->{BlowfishCrypt} = {
            cost        => 4,
            key_nul     => 1,
            salt_random => 128,
        };
    }

    $config->{package} = $config->{default};

    return bless {
        config      => $config,
        passphrase  => $plaintext,
    }, 'Dancer::Plugin::Passphrase';
}


=head1 METHODS

=head2 passphrase->generate_hash

Generates and returns an RFC 2307 representation of the plaintext password
that is suitable for storage in a database.

    my $hash = passphrase('my password')->generate_hash;

You can pass a hashref of options to specify what kind of hash should be 
generated. You can specify any options that you can set in the config file.

Refer to the documentation for L<Authen::Passphrase> for which options 
are applicable for a given scheme.

    my $hash = passphrase('my password')->generate_hash({
        package     => '', # Module in Authen::Passphrase namespace
        algorithm   => '', # Algorithm if using SaltedDigest package
        cost        => '', # Cost / Work Factor if using BlowfishCrypt package
        salt        => '', # Raw salt
        salt_hex    => '', # Hex version of the salt
        salt_base64 => '', # Base 64 encoded salt
        salt_random => '', # Length of randomly generated salt 
    });

=cut

sub generate_hash {
    my ($self, $options) = @_;

    $self->_get_settings($options);
    $self->_add_random_salt;

    return $self->_add_recogniser->_all_information if wantarray;
    return $self->_add_recogniser->_as_extended_rfc2307;
}



=head2 passphrase->matches

Matches a plaintext password against a stored hash.
Returns true if the hash of the password matches the stored hash.
Returns false if they don't match or if there was an error creating the hash.

    passphrase('my password')->matches($stored_hash);

If you pass a scalar, it must be a valid RFC 2307 or crypt string.

You can pass a hashref of options if you need to provide extra information
about the composition of the hash. Not all options are required, see the 
documentation for L<Authen::Passphrase> for which options are applicable for a given scheme

    passphrase('my password')->matches({
        package     => '', # Module in Authen::Passphrase namespace
        algorithm   => '', # Algorithm if using SaltedDigest package
        cost        => '', # Cost / Work Factor if using BlowfishCrypt package
        salt        => '', # Raw salt
        salt_hex    => '', # Hex version of the salt
        salt_base64 => '', # Base 64 encoded salt
        hash        => '', # Raw hash
        hash_hex    => '', # Hex version of the hash
        hash_base64 => '', # Base 64 encoded hash
    });

=cut

sub matches {
    my ($self, $options) = @_;

    $self->_get_settings($options);

    my $hash = $self->_add_recogniser->_as_extended_rfc2307;
    return Authen::Passphrase->from_rfc2307($hash)->match($self->{passphrase});
}


=head2 passphrase->generate_random

Generates and returns 16 cryptographically random
characters from the url-safe base64 charater set.

    my $rand_pass = passphrase->generate_random;

The passwords generated are suitable for use as
temporary passwords or one-time authentication tokens.

You can configure the length and the character set
used by passing a hashref of options.

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


# Gets default settings for a package from config.yml
sub _get_settings {
    my ($self, $options) = @_;

    if ($options->{package}) {
        $self->{config}->{$options->{package}} = {
            %{$self->{config}->{$options->{package}}},
            %{$options},
        };

        $self->{config}->{package} = $options->{package};
    }    
}


# Adds a random salt if we know the algorithm and we've not specified salt explicitly
sub _add_random_salt {
    my ($self) = @_;

    # Amount of salt in bytes. It should be as long as the final hash function
    my $salt_length = {
        'SHA-512' => 64, 'SHA-384' => 48,
        'SHA-256' => 32, 'SHA-224' => 28,
        'SHA-1'   => 20, 'MD5'     => 16,
        'MD4'     => 16,
    };

    my $current_package   = $self->{config}->{package};
    my $current_algorithm = $self->{config}->{$current_package}->{algorithm};

    unless ( grep /^salt/, keys %{ $self->{config}->{$current_package} } ) {    
        if ($current_algorithm) {
            $self->{config}->{$current_package}->{salt_random} = $salt_length->{ $current_algorithm };
        }
    }
}


# Adds the required Authen::Passphrase recogniser object on demand.
sub _add_recogniser {
    my ($self) = @_;

    my $config  = $self->{config}->{ $self->{config}->{package} };

    # Decode & add both the hash and salt if we want a recogniser from a stored hash.
    # Specifying a random salt is silly if we want to verify an existing hash, so delete it even if specified.
    if ( grep /^hash/, keys %{$config} ) {
        $config->{hash} = $config->{hash} || pack("H*", $config->{hash_hex}) || decode_base64($config->{hash_base64});
        $config->{salt} = $config->{salt} || pack("H*", $config->{salt_hex}) || decode_base64($config->{salt_base64});
        delete $config->{salt_random};
    } else {
        $config->{passphrase} = $self->{passphrase};
    }

    # Cleanup options that are invalid when passed to Authen::Passphrase
    for (qw(default package hash_hex hash_base64 salt_hex salt_base64)) {
        delete $config->{$_};
    }

    $self->{recogniser} = use_module("Authen::Passphrase::$self->{config}->{package}")->new(
         %{$config}
    );

    return $self;
}


# Returns all information about a generated hash
sub _all_information {
    my ($self) = @_;

    my @potential = qw(salt hash cost key_nul as_crypt algorithm);

    my %defined;
    for my $method (@potential) {
        if ($self->{recogniser}->can($method)) {
            $defined{$method} = $self->{recogniser}->$method;
        }
    }

    # Some Authen::Passphrase modules provide these functions - but not all
    for (qw(salt hash)) {
        $defined{$_.'_hex'}     = unpack("H*", $defined{$_})      if $defined{$_};
        $defined{$_.'_base64'}  = encode_base64($defined{$_}, '') if $defined{$_};
    }

    $defined{'passphrase'}   = $self->{passphrase};
    $defined{'rfc_2307'}     = $self->_as_extended_rfc2307;

    return %defined;
}


# Unofficial extensions to the RFC that are widely supported
sub _as_extended_rfc2307 {
    my ($self) = @_;

    my $r = $self->{recogniser};

    if ($r->{algorithm} ~~ [qw(SHA-224 SHA-256 SHA-384 SHA-512)]) {
        my $scheme = $r->{algorithm};
        $scheme =~ s/-//;

        # Check for salt and add the S prefix if it has.
        return "{".($r->{salt} eq "" ? "" : "S").$scheme."}".encode_base64($r->{hash}.$r->{salt}, '');
    }

    return $r->as_rfc2307() if $r->can('as_rfc2307');
    return '{CRYPT}'.$r->as_crypt() if $r->can('as_crypt');

    # Default to RejectAll, better to fail secure than fail safe
    return '{CRYPT}*';
}


register_plugin;

1;


=head1 DESCRIPTION

=head2 Purpose

The aim of this module is to help you store new passwords in a secure manner, 
whilst still being able to verify and upgrade older passwords.

Cryptography is a vast and complex field. Many people try to roll their own 
methods for securing user data, but succeed only in coming up with 
a system that has little real security.

This plugin provides a simple way of managing that complexity, allowing 
developers to follow best crypto practice without having to become a cryptography expert.

To ease the transition from a custom solution, this plugin is built
on top of C<Authen::Passphrase>, an excellent module that provides an interface 
to many common and uncommon hashing schemes. This module supports every scheme that 
C<Authen::Passphrase> does.

See the cookbook for some ideas on how to to move from older schemes.

=head2 Rationale

The module defaults to hasing passwords using the bcrypt algorithm, returning them
in RFC 2307 format.

RFC 2307 describes an encoding system for passphrase hashes, as used in the "userPassword"
attribute in LDAP databases. It encodes hashes as ASCII text, and supports several 
passphrase schemes by starting the encoding with an alphanumeric scheme identifier enclosed 
in braces.

Bcrypt is an adaptive hashing algorithm that is designed to resist brute 
force attacks by including a cost (aka work factor). This cost increases 
the computational effort it takes to compute the hash.

SHA and MD5 are designed to be fast, and modern machines compute a billion 
hashes a second. With computers getting faster every day, brute forcing 
SHA hashes is a very real problem that cannot be easily solved.

Increasing the cost of generating a bcrypt hash is a trivial way to make 
brute forcing ineffective. With a low cost setting, bcrypt is just as secure 
as a more traditional SHA+salt scheme, and around the same speed.

For a more detailed description of why bcrypt is preferred, see this article: 
L<http://codahale.com/how-to-safely-store-a-password/>

=head2 Common Mistakes

Common mistakes people make when creating their own solution. If any of these 
seem familiar, you should probably be using this module

=over

=item Passwords are stored as plain text for a reason

There is never a valid reason to store a password as plain text.
Passwords should be reset and not emailed to customers when they forget.
Support people should be able to login as a user without knowing the users password.
No-one except the user should know the password - that is the entire point.

=item No-one will ever guess our super secret algorithm!

Unless you're a cryptography expert with many years spent studying 
super-complex maths, your algorithm is almost certainly not as secure 
as you think. Just because it's hard for you to break doesn't mean
it's difficult for a computer.

=item Our application-wide salt is "Sup3r_S3cret_L0ng_Word" - No-one will ever guess that.

This is common misunderstanding of what a salt is meant to do. The purpose of a 
salt is to make sure the same password doesn't always generate the same hash.
A fresh salt needs to be created each time you hash a password. It isn't meant 
to be a secret key.

=item We generate our random salt using C<rand>.

C<rand> isn't actually random, it's a non-unform pseudo-random number generator, 
and not suitable for cryptographic applications.

=item We use C<md5(pass.salt)>, and the salt is from C</dev/random>

MD5 has been broken for many years. Commodity hardware can find a 
hash collision in seconds, meaning an attacker can easily generate 
the correct MD5 hash without using the correct password.

=item We use C<sha(pass.salt)>, and the salt is from C</dev/random>

SHA isn't quite as broken as MD5, but it shares the same theoretical 
weaknesses. Even without hash collisions, it is vulnerable to brute forcing.
Modern hardware is so powerful it can try around a billion hashes a second. 
That means every 7 chracter password in the range [A-Za-z0-9] can be cracked 
in one hour on your average desktop computer.

=item If the only way to break the hash is to brute-force it, it's secure enough

Whilst it is unlikely that your database will be hacked and your hashes 
brute forced, because this module is easy to integrate into existing codebases, 
creates hashes that are resistant to brute forcing, and still validates your 
old hashes, there are few reasons not to use this module.

=back


=head1 CONFIGURATION

In your applications config file, you can set the default C<Authen::Passphrase> object 
and the default settings for that object. 

You can override these defaults when you call C<generate_hash>.

If you do no configuration at all, it defaults to BlowfishCrypt with a cost of 7.

    plugins:
        Passphrase:
            default: BlowfishCrypt
        
            BlowfishCrypt:
                cost: 8
                
            SaltedDigest:
                algorithm: 'SHA-1'
                salt_random: 20


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

