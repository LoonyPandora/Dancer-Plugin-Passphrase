package Dancer::Plugin::Passphrase;

# ABSTRACT: Passphrases and Passwords as objects for Dancer

=head1 NAME

Dancer::Plugin::Passphrase - Passphrases and Passwords as objects for Dancer

=head1 SYNOPSIS

This plugin manages the hashing of passwords for Dancer apps, allowing 
developers to follow cryptography best practices without having to 
become a cryptography expert.

It uses the bcrypt algorithm as the default, wrapping L<Crypt::Eksblowfish::Bcrypt>, 
while also supporting any hashing function provided by L<Digest> 

=head1 USAGE

    package MyWebService;
    use Dancer ':syntax';
    use Dancer::Plugin::Passphrase;

    post '/login' => sub {
        my $phrase = passphrase( param('my password') )->generate;

        # $phrase is now an object that contains RFC 2307 representation
        # of the hashed passphrase, along with the salt and the raw_hash
        
        # You should store $phrase->rfc2307() for use in the matches() method
    };

    get '/protected' => sub {
        # Retrieve $stored_rfc_2307_string - which MUST be a valid RFC 2307
        # string of the kind returned by the rfc2307() method

        if ( passphrase( param('my password') )->matches( $stored_rfc_2307 ) ) {
            # Passphrase matches!
        }
    };

    get '/generate_new_password' => sub {
        return passphrase->generate_random;
    };

=cut

use strict;
use feature 'switch';

use Dancer::Plugin;

use Crypt::Eksblowfish::Bcrypt qw(bcrypt en_base64 de_base64);
use Carp qw(carp croak);
use Data::Dump qw(dump);
use Data::Entropy qw(entropy_source with_entropy_source);
use Data::Entropy::Algorithms qw(rand_bits rand_int);
use Data::Entropy::RawSource::Local;
use Data::Entropy::Source;
use Digest;
use MIME::Base64 qw(decode_base64 encode_base64);

our $VERSION = '1.1.0';

# Auto stringifies and returns the RFC 2307 representation
# of the object unless we are calling a method on it
use overload (
    '""' => 'rfc2307'
);

register passphrase => \&passphrase;


=head1 KEYWORDS

=head2 passphrase

Given a plaintext password, it returns a Dancer::Plugin::Passphrase 
object that you can generate a new hash from, or match against a stored hash.

=cut

sub passphrase {
    my $plaintext = shift;

    return bless {
        plaintext => $plaintext
    }, 'Dancer::Plugin::Passphrase';
}



=head1 METHODS

=head2 passphrase->generate

Generates an RFC 2307 representation of the hashed passphrase
that is suitable for storage in a database.

    my $pass = passphrase('my passphrase')->generate;

You should store C<$phrase->rfc_2307()> in your database. For convenience
the object will automagically return the RFC 2307 representation when no
method is called on it.

Accepts a hashref of options to specify what kind of hash should be 
generated. All options settable in the config file are valid.

If you specify only the algorithm, the default settings for that algorithm will be used.

A cryptographically random salt is used if salt is not defined.
Only if you specify the empty string will an empty salt be used
This is not recommended, and should only be used to upgrade old insecure hashes

    my $phrase = passphrase('my password')->generate({
        algorithm  => '',   # What algorithm is used to generate the hash
        cost       => '',   # Cost / Work Factor if using bcrypt 
        salt       => '',   # Manually specify salt if using a salted digest
    });

=cut

sub generate {
    my ($self, $options) = @_;

    $self->_get_settings($options);
    $self->_calculate_hash;

    return $self;
}

# For backwards compatibility
*generate_hash = \&generate;



=head2 passphrase->matches

Matches a plaintext password against a stored hash.
Returns 1 if the hash of the password matches the stored hash.
Returns undef if they don't match or if there was an error
Fail-Secure, rather than Fail-Safe.

    passphrase('my password')->matches($stored_rfc_2307_string);

$stored_rfc_2307_string B<MUST> be a valid RFC 2307 string,
as created by L<generate()|/"passphrase__generate">

An RFC 2307 string is made up of a scheme identifier, followed by a
base64 encoded string. The base64 encoded string should contain
the password hash and the salt concatenated together - in that order.

    '{'.$scheme.'}'.encode_base64($hash . $salt, '');

Where C<$scheme> can be any of the following and their unsalted variants,
which have the leading S removed. CRYPT is always salted.

    SMD5 SSHA SSHA224 SSHA256 SSHA384 SSHA512 CRYPT

A complete RFC2307 string looks like this:

    {SSHA}K3LAbIjRL5CpLzOlm3/HzS3qt/hUaGVTYWx0

This is the format created by L<generate()|/"passphrase__generate">

=cut

sub matches {
    my ($self, $stored_hash) = @_;
    my ($rfc2307_scheme, $salt_and_digest) = ($stored_hash =~ m/^{(\w+)}(.*)/s);

    if (!$rfc2307_scheme || !$salt_and_digest) {
        die "An RFC 2307 compliant string must be passed to matches()";
    }

    if ($rfc2307_scheme eq 'CRYPT') {
        my $calculated_hash = bcrypt($self->{plaintext}, $salt_and_digest);

        return 1 if $salt_and_digest eq $calculated_hash;        
        return undef;
    } else {
        my ($salt, $digest, $algorithm);

        if (_salt_offset()->{$rfc2307_scheme}) {
            $salt      = substr(decode_base64($salt_and_digest),    _salt_offset()->{$rfc2307_scheme});
            $digest    = substr(decode_base64($salt_and_digest), 0, _salt_offset()->{$rfc2307_scheme});
            $algorithm = $rfc2307_scheme;
            $algorithm =~ s/^S//;
        } else {
            $salt      = '';
            $digest    = decode_base64($salt_and_digest);
            $algorithm = $rfc2307_scheme;
        }

        # Digest:: module names have dashes in them. $scheme names do not.
        $algorithm =~ s/SHA/SHA-/;
        $algorithm = 'SHA-1' if $algorithm eq 'SHA-';
        $algorithm = ucfirst lc $algorithm if $algorithm eq 'WHIRLPOOL';

        $self->{salt}   = $salt;
        $self->{scheme} = $algorithm;

        $self->_calculate_hash();

        return 1 if $self->raw_hash eq $digest;
        return undef
    }

}



=head2 passphrase->generate_random

Generates and returns any number of cryptographically random
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



=head1 ADDITIONAL METHODS

=head2 rfc2307

Returns the rfc2307 representation from a C<Dancer::Plugin::Passphrase> object.

    passphrase('my password')->generate->rfc2307;

=cut

sub rfc2307 {
    my $self = shift;

    return undef unless $self->{rfc2307};
    return $self->{rfc2307};
}

# For backwards compatibility
*as_rfc2307 = \&rfc2307;


=head2 scheme

Returns the scheme name from a C<Dancer::Plugin::Passphrase> object.

This is the scheme name as used in the RFC 2307 representation

    passphrase('my password')->generate->scheme;

=cut

sub scheme {
    my $self = shift;

    return undef unless $self->{scheme};
    return $self->{scheme};
}


=head2 algorithm

Returns the algorithm name from a C<Dancer::Plugin::Passphrase> object.

This is the algorithm in the C<Digest::> namespace that was used to 
generate the hash.

    passphrase('my password')->generate->algorithm;

=cut

sub algorithm {
    my $self = shift;

    return undef unless $self->{algorithm};
    return $self->{algorithm};
}


=head2 cost

Returns the bcrypt cost from a C<Dancer::Plugin::Passphrase> object.
Only works when using the bcrypt algorithm, returns undef for other algorithms

    passphrase('my password')->generate->cost;

=cut

sub cost {
    my $self = shift;

    return undef unless $self->{cost};
    return $self->{cost};
}


=head2 raw_salt

Returns the raw salt from a C<Dancer::Plugin::Passphrase> object.

    passphrase('my password')->generate->raw_salt;

=cut

sub raw_salt {
    my $self = shift;

    return undef unless $self->{salt};
    return $self->{salt};
}


=head2 raw_hash

Returns the raw hash from a C<Dancer::Plugin::Passphrase> object.

    passphrase('my password')->generate->raw_hash;

=cut

sub raw_hash {
    my $self = shift;

    return undef unless $self->{hash};
    return $self->{hash};
}


=head2 salt_hex

Returns the hex-encoded salt from a C<Dancer::Plugin::Passphrase> object.

    passphrase('my password')->generate->salt_hex;

=cut

sub salt_hex {
    my $self = shift;

    return undef unless $self->{salt};
    return unpack("H*", $self->{salt});
}


=head2 hash_hex

Returns the hex-encoded hash from a C<Dancer::Plugin::Passphrase> object.

    passphrase('my password')->generate->hash_hex;

=cut

sub hash_hex {
    my $self = shift;

    return undef unless $self->{hash};
    return unpack("H*", $self->{hash});
}


=head2 salt_base64

Returns the base64 encoded salt from a C<Dancer::Plugin::Passphrase> object.

    passphrase('my password')->generate->salt_base64;

=cut

sub salt_base64 {
    my $self = shift;

    return undef unless $self->{salt};
    return encode_base64($self->{salt}, '');
}


=head2 hash_base64

Returns the base64 encoded hash from a C<Dancer::Plugin::Passphrase> object.

    passphrase('my password')->generate->hash_base64;

=cut

sub hash_base64 {
    my $self = shift;

    return undef unless $self->{hash};
    return encode_base64($self->{hash}, '');
}

=head2 plaintext

Returns the plaintext password as originally supplied to the L<passphrase> keyword.

    passphrase('my password')->generate->plaintext;

=cut

sub plaintext {
    my $self = shift;

    return undef unless $self->{plaintext};
    return $self->{plaintext};
}



# Actual generation of the hash, using the provided settings
sub _calculate_hash {
    my $self = shift;

    # All supported hash schemes
    if ($self->algorithm ~~ [qw(MD5 SHA-1 SHA-224 SHA-256 SHA-384 SHA-512 BCRYPT)]) {
        carp "Boo - $self->{algorithm}";
    } else {
        carp "FOO - $self->{algorithm}";
    }

    # Be extra nice, and accept bcrypt case insensitvely
    $self->{algorithm} = 'Bcrypt' if $self->{algorithm} =~ m/bcrypt/i;
    
    
    
    
    
    # $self->{algorithm} = uc $self->{scheme};
    # $rfc2307_scheme =~ s/\W+//;


    my $hash = Digest->new( $self->{algorithm} );


    given ($self->{algorithm}) {
        when ('Bcrypt') {
            $hash->salt($self->{salt});
            $hash->cost($self->{cost});
        }
        when ('PBKDF2') {
            $hash->salt($self->{salt});
            $hash->cost($self->{cost});
        }
        default {
            $hash->add($self->{plaintext});
            $hash->add($self->{salt});
        }
    }

    


    # $self->{hash}    = $hash->digest;
    # $self->{rfc2307} = '{'.$rfc2307_scheme.'}'.
    #                    encode_base64($self->{hash}.$self->{salt}, '');

    # carp $self->scheme . " - " . $hash->hexdigest;


    # if (uc $self->{scheme} eq 'BCRYPT') {    
    #     my $template     = join('$', '$2a', $self->{cost}, en_base64($self->{salt}));
    #     $self->{hash}    = bcrypt($self->{plaintext}, $template);
    #     # carp dump $self;
    #     $self->{rfc2307} = '{CRYPT}'.$self->{hash};
    # } else {
    #     my $rfc2307_scheme = uc $self->{scheme};
    #     $rfc2307_scheme =~ s/\W+//;
    # 
    # 
    #     $rfc2307_scheme = 'SHA'   if $rfc2307_scheme eq 'SHA1';
    #     $rfc2307_scheme = 'CRYPT' if $rfc2307_scheme eq 'BCRYPT';
    # 
    # 
    #     # $rfc2307_scheme;
    # 
    # 
    #     if ($self->{salt}) {
    #         $rfc2307_scheme = 'S'.$rfc2307_scheme;
    #     }
    # 
    #     # carp $self->{scheme};
    # 
    #     my $hash = Digest->new( $self->{scheme} );
    # 
    #     $hash->add($self->{plaintext});
    #     $hash->add($self->{salt});
    # 
    #     $self->{hash}    = $hash->digest;
    #     $self->{rfc2307} = '{'.$rfc2307_scheme.'}'.
    #                        encode_base64($self->{hash}.$self->{salt}, '');
    # 
    # }

    return $self;
}


# Gets the settings from config.yml, and merges them with any custom
# settings given to the constructor
sub _get_settings {
    my ($self, $options) = @_;

    $self->{algorithm} = $options->{algorithm} || plugin_setting->{algorithm} || 'BCRYPT';
    my $plugin_setting = plugin_setting->{$self->{algorithm}};

    if ($options->{true_random_salt} // $plugin_setting->{true_random_salt}) {
        $self->{true_random_salt} = 1;
    }

    # Specify empty string to get an unsalted hash
    $self->{salt} = $options->{salt} //
                    $plugin_setting->{salt} //
                    _random_salt($self->{true_random_salt});

    # Bcrypt requires salt and a cost parameter
    if (uc $self->{algorithm} eq 'BCRYPT') {
        $self->{cost} = $options->{cost} ||
                        $plugin_setting->{cost} ||
                        4;

        $self->{cost} = 31 if $self->{cost} > 31;
        $self->{cost} = sprintf("%02d", $self->{cost});

        $self->{salt} = _random_salt($self->{true_random_salt});
    }

    return $self;
}


# Generates 128 bits of entropy to use as a salt. bcrypt requires
# exactly this amount, and it's a reasonable amount for other algorithms
sub _random_salt {
    my ($true_random_salt) = @_;
    my $entropy_source;

    # This is truly random, but potentially blocks - hence it's not the default
    if ($true_random_salt) {
        $entropy_source = Data::Entropy::Source->new(
            Data::Entropy::RawSource::Local->new, 'sysread'
        );
    }

    return with_entropy_source $entropy_source, sub {
        entropy_source->get_bits('128');
    };
}


# Length of a hash in octets. Used to separate salt from a hash
sub _salt_offset {
    return {
        'SMD4'       => 128 / 8,
        'SMD5'       => 128 / 8,
        'SSHA'       => 160 / 8,
        'SSHA224'    => 224 / 8,
        'SSHA256'    => 256 / 8,
        'SSHA384'    => 384 / 8,
        'SSHA512'    => 512 / 8,
        'SWHIRLPOOL' => 512 / 8,
    };
}



register_plugin;

1;


=head1 MORE INFORMATION

=head2 Purpose

The aim of this module is to help you store new passwords in a secure manner, 
whilst still being able to verify and upgrade older passwords.

Cryptography is a vast and complex field. Many people try to roll their own 
methods for securing user data, but succeed only in coming up with 
a system that has little real security.

This plugin provides a simple way of managing that complexity, allowing 
developers to follow crypto best practice without having to become an expert.


=head2 Rationale

The module defaults to hashing passwords using the bcrypt algorithm, returning them
in RFC 2307 format.

RFC 2307 describes an encoding system for passphrase hashes, as used in the "userPassword"
attribute in LDAP databases. It encodes hashes as ASCII text, and supports several 
passphrase schemes by starting the encoding with an alphanumeric scheme identifier enclosed 
in braces.

RFC 2307 only specifies the C<MD5>, and C<SHA> schemes - however in real-world usage,
schemes that are salted are widely supported, and are thus provided by this module.

Bcrypt is an adaptive hashing algorithm that is designed to resist brute 
force attacks by including a cost (aka work factor). This cost increases 
the computational effort it takes to compute the hash.

SHA and MD5 are designed to be fast, and modern machines compute a billion 
hashes a second. With computers getting faster every day, brute forcing 
SHA hashes is a very real problem that cannot be easily solved.

Increasing the cost of generating a bcrypt hash is a trivial way to make 
brute forcing ineffective. With a low cost setting, bcrypt is just as secure 
as a more traditional SHA+salt scheme, and just as fast. Increasing the cost
as computers become more powerful keeps you one step ahead

For a more detailed description of why bcrypt is preferred, see this article: 
L<http://codahale.com/how-to-safely-store-a-password/>


=head2 Configuration

In your applications config file, you can set the default hashing algorithm,
and the default settings for every supported algorithm. Calls to
L<generate()|/"passphrase__generate"> will use the default settings
for that algorithm specified in here.

You can override these defaults when you call L<generate()|/"passphrase__generate">.

If you do no configuration at all, the default is to bcrypt with a cost of 4, and 
a strong psuedo-random salt.

    plugins:
        Passphrase:
            default: bcrypt

            bcrypt:
                cost: 8


=head2 Storage in a database

You should be storing the RFC 2307 string in your database, it's the easiest way
to use this module. You could store the C<raw_salt>, C<raw_hash>, and C<scheme>
separately, but this strongly discouraged. RFC 2307 strings are specifically
designed for storing hashed passwords, and should always be used.

The length of the string produced by L<generate()|/"passphrase__generate"> can
vary dependent on your settings. Below is a table of the lengths generated
using default settings.

You will need to make sure your database columns are at least this long.
If the string gets truncated, the password can I<never> be validated.

    SCHEME      LENGTH  EXAMPLE RFC 2307 STRING

    CRYPT       68      {CRYPT}$2a$04$MjkMhQxasFQod1qq56DXCOvWu6YTWk9X.EZGnmSSIbbtyEBIAixbS
    SSHA512     118     {SSHA512}lZG4dZ5EU6dPEbJ1kBPPzEcupFloFSIJjiXCwMVxJXOy/x5qhBA5XH8FiUWj7u59onQxa97xYdqje/fwY5TDUcW1Urplf3KHMo9NO8KO47o=
    SSHA384     98      {SSHA384}SqZF5YYyk4NdjIM8YgQVfRieXDxNG0dKH4XBcM40Eblm+ribCzdyf0JV7i2xJvVHZsFSQNcuZPKtiTMzDyOU+w==
    SSHA256     74      {SSHA256}xsJHNzPlNCpOZ41OkTfQOU35ZY+nRyZFaM8lHg5U2pc0xT3DKNlGW2UTY0NPYsxU
    SSHA224     70      {SSHA224}FTHNkvKOdyX1d6f45iKLVxpaXZiHel8pfilUT1dIZ5u+WIUyhDGxLnx72X0=
    SSHA        55      {SSHA}Qsaao/Xi/bYTRMQnpHuD3y5nj02wbdcw5Cek2y2nLs3pIlPh
    SMD5        51      {SMD5}bgfLiUQWgzUm36+nBhFx62bi0xdwTp+UpEeNKDxSLfM=

=head2 Common Mistakes

Common mistakes people make when creating their own solution. If any of these 
seem familiar, you should probably be using this module

=over

=item Passwords are stored as plain text for a reason

There is never a valid reason to store a password as plain text.
Passwords should be reset and not emailed to customers when they forget.
Support people should be able to login as a user without knowing the users password.
No-one except the user should know the password - that is the point of authentication.

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
and not suitable for cryptographic applications. Whilst this module also defaults to 
a PRNG, it is better than the one provided by C<rand>. Using a true RNG is a config
option away, but is not the default as it it could potentially block output if the
system does not have enough entropy to generate a truly random number

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

It is unlikely that your database will be hacked and your hashes brute forced.
However, in the event that it does happen, or SHA512 is broken, using this module
gives you an easy way to change to a different algorithm, while still allowing
you to validate old passphrases

=back


=head1 KNOWN ISSUES

If you see errors like this

    Wide character in subroutine entry

or

    Input must contain only octets

The C<MD5> and C<bcrypt> algorithms can't handle chracters with an ordinal
value above 255, producing errors like this if they encounter them.
It is not possible for this plugin to automagically work out the correct
encoding for a given string.

If you see errors like this, then you probably need to use the L<Encode> module
to encode your text as UTF-8 (or whatever encoding it is) before giving it 
to C<passphrase>.

Text encoding is a bag of hurt, and errors like this are probably indicitive
of deeper problems within your app's code.

You will save yourself a lot of trouble if you read up on the
L<Encode> module sooner rather than later.

For further reading on UTF-8, unicode, and text encoding in perl,
see L<http://training.perl.com/OSCON2011/index.html>


=head1 SEE ALSO

L<Dancer>, L<Digest>, L<Crypt::Eksblowfish::Bcrypt>, L<Dancer::Plugin::Bcrypt>


=head1 AUTHOR

James Aitken <jaitken@cpan.org>


=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2012 by James Aitken.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut

