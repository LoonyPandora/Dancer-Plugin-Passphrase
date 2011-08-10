package Dancer::Plugin::Passphrase;

# ABSTRACT: Passphrases and Passwords as objects for Dancer

use strict;

use Dancer::Plugin;
use Dancer::Config;
use Authen::Passphrase;
use Data::Dumper;
use Module::Runtime qw(use_module);
use MIME::Base64;

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

    my $pass = use_module("Authen::Passphrase::$package")->new(
         %{$config}, (passphrase => $self->{passphrase})
    );


    # Algorithms that aren't in the RFC, but commonly used in LDAP userPasswords
    if ($config->{algorithm} ~~ [qw(SHA-224 SHA-256 SHA-384 SHA-512)]) {
        my $scheme = $config->{algorithm};


        

        $scheme =~ s/-//;
        my $rfc = "{".($pass->{salt} eq "" ? "" : "S").$scheme."}".encode_base64($pass->{hash}.$pass->{salt}, '');
        #die Dumper($pass);

        #die Dumper($rfc);

        #return 
    }


    # Return a bunch of useful info if we want.
    # Cleaner than lots of methods.
    if (wantarray) {

    }


    return $pass->_extended_rfc2307();
}


# Returns true if password matches, empty string if not
sub matches {
    my ($self, $options) = @_;

    # $options should be rfc2307 string, crypt string, 
    # or a hashref of options needed to construct an rfc2307 string.
    my $hash;
    if (ref($options) eq 'HASH') {
        my $hash = $options->{hash} || pack("H*", $options->{hash_hex});
        $hash = '{'.$options->{scheme}.'}'.MIME::Base64::encode_base64($hash.$options->{salt}, '');
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

    my $scheme = $self->{algorithm};
    $scheme =~ s/-//;

    if ($self->{algorithm} ~~ [qw(SHA-224 SHA-256 SHA-384 SHA-512)]) {
        return "{".($self->{salt} eq "" ? "" : "S").$scheme."}".encode_base64($self->{hash}.$self->{salt}, '');
    }

    return $self->as_rfc2307();
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




    # Scheme is rfc2307 scheme name
    # Algorithm is the Digest method (sha-1, sha-256, etc)
    # Package is the Authen::Pass packagename (SaltedDigest, BlowfishCrypt)


Aim is to enable developers to stop worrying about these solved problems, and move on to the rest of their app.

Few devs are crypto experts and will either waste a lot of time figuring out how to make things secure, or will end up with a system
that SEEMS secure to them, but in actual fact is not secure.

This module gives secure generation and storage of passwords. It makes it hard to generate code that is not secure.
It provdides an easy upgrade path to other modules, and stores passwords in as standard a format as possible.

It strives to be a drop in replacement for older code, so one can use this plugin with leagacy applications,
then flick the switch to a more secure method. i.e passwords are currently stored as unsalted md5 - this module can work with that.
New code you write from then on can store passwords as bcrypt, while still verifying against the old passwords.
When user logs in you can upgrade the old passwords

May need to store the salt / hash / scheme in seperate DB columns, so being able to get that from a hash would be useful.



my $pass_object = password('plaintext');

$pass_object->generate_hash(); 
$pass_object->matches('$hash');

my $hashed_pw = password('plaintext')->generate_hash();
my %password_details = password('plaintext')->generate_hash();


my $generated_password = password();
my $generated_password = password->generate_randon();


https://www.opends.org/wiki/page/TheUserPasswordAttributeSyntax
Add support for:
{SSHA224}, {SSHA256}, {SSHA384}, {SSHA512}
{SHA224}, {SHA256}, {SHA384}, {SHA512}




password('plaintext');
password('plaintext')->matches('hash');

password('plaintext')->generate_hash({});

password()->generate_hash({});




List context, returns hash.

my %password_details = password('plaintext');

salt => '',
cost => '',
hash => '',
crypt_string => '',
rfc_2307 => '',
hash_base64 => '',


scalar context, returns rfc_2307


void context, returns object.



CURRENT:

password->extract_salt('$hash');
password->extract_hash('$hash');
password->extract_scheme('$hash');
password->generate_hash('plaintext');
password->generate_salt();
password->generate_password();
password->is_valid('plaintext', 'hashed_pass');

password->generate_hash('plaintext', {
    scheme => 'bcyrpt',
    salt   => 'random',
    cost   => 8,
});

password->generate_password({
    length => 8
});

password->is_valid('plaintext', 'hashed_pass', {
    scheme => 'bcyrpt',
    salt   => 'random',
    cost   => 8,
});



