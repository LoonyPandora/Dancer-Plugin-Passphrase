package Dancer::Plugin::Passphrase;

# ABSTRACT: Passphrases and Passwords as objects for Dancer

use strict;

use Dancer::Plugin;
use Dancer::Config;
use Authen::Passphrase;
use Data::Dumper;
use Module::Runtime qw(use_module);


our $VERSION = '0.0.1';



register password => \&password;


sub password {
    # Default settings, so it works out of the box should contain all possible settings
    my $defaults = {
        scheme => 'BlowfishCrypt',
        BlowfishCrypt => {
            cost        => 4,
            salt_random => 1
        },
        SaltedDigest => {
            algorithm   => 'SHA-1',
#            salt_random => 1,
        },
    };

    # Read the settings from config.yml - they override the defaults above.
    my $settings = {};
    for my $key (keys %{$defaults}) {
        if (ref($defaults->{$key}) eq 'HASH') {   
            %{$settings->{$key}} = (%{$defaults->{$key}}, %{plugin_setting->{$key}});
        } else {
            $settings->{$key} = plugin_setting->{$key} || $defaults->{$key};
        }
    }

    return bless { settings => $settings }, 'Dancer::Plugin::Passphrase';
}



sub is_valid {
    my ($self, $plaintext, $hash, $options) = @_;

    # We are forcing the check to be a specific scheme, so manually hash the plaintext
    if ($options) {
        my $config = $self->_get_config($options);
        my $encoding = $config->{settings}->{encoding} || 'hash_hex';
        delete $config->{settings}->{encoding};

        my $passphrase = use_module("Authen::Passphrase::$config->{scheme}")->new(
             %{$config->{settings}}, (passphrase => $plaintext)
        );
        
        if ($hash eq $passphrase->$encoding()) {
            return 1;
        }

        return undef;
    }

    # TODO: Force checks using options
    # Create a crypt string and use the recognizer below.
    if (my $recogniser = _get_recogniser($hash)) {
        return $recogniser->match($plaintext);
    }
    
    return undef;
}


sub extract_salt {
    my ($self, $hash) = @_;
    $self->_extract_item('salt', $hash);
}

sub extract_hash {
    my ($self, $hash) = @_;
    $self->_extract_item('hash', $hash);
}

sub extract_algorithm {
    my ($self, $hash) = @_;
    $self->_extract_item('algorithm', $hash);
}

sub extract_cost {
    my ($self, $hash) = @_;
    $self->_extract_item('cost', $hash);
}





sub generate_hash {
    my ($self, $plaintext, $options) = @_;

    my $config = $self->_get_config($options);

    my $passphrase = use_module("Authen::Passphrase::$config->{scheme}")->new(
         %{$config->{settings}}, (passphrase => $plaintext)
    );

    Dancer::Logger::error($passphrase->hash());

    # TODO: If can't be stored as rfc2307 format return the hash raw
    return $passphrase->as_rfc2307();
}



sub _extract_item {
    my ($self, $type, $hash) = @_;
    my $recogniser = _get_recogniser($hash);
    return $recogniser->$type() if $recogniser->can($type);
}


sub _get_recogniser {
    my ($hash) = @_;

    if ($hash =~ /^{\w+}/) {
        return Authen::Passphrase->from_rfc2307($hash);
    } elsif ($hash =~ /^\$\w+\$/) {
        return Authen::Passphrase->from_crypt($hash);
    }

    # We should have built a valid crypt string before trying the recogniser
    die 'unrecognized storage format';
}


sub _get_config {
    my ($self, $args) = @_;
    $args = {} if !$args;

    my $scheme = $args->{scheme} || $self->{settings}->{scheme};
    delete $args->{scheme} if $args->{scheme};

    my $settings = {
        %{$self->{settings}->{$scheme}},  # Default settings are...
        %{$args},                         # Overridden by arguments.
    };

    # Unless salt is manually specified (which you shouldn't do unless you know what you're doing)
    # We generate a random salt, the same length as the hash we are creating.
    unless ( grep /^salt/, keys %{$settings}) {
        if ($settings->{algorithm} eq 'SHA-1') {
            $settings->{salt_random} = 20;
        } else {
            $settings->{salt_random} = 40;
        }
    }

    return {
        scheme   => $scheme,
        settings => $settings,
    };
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

May need to store the salt / hash / scheme in seperate DB columns, so being able to get that from a hash would be useful.



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



