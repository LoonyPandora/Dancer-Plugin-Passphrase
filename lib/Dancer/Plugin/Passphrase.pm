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
    my $args = shift;

    return bless {}, 'Dancer::Plugin::Passphrase';
}

# password->generate('plaintext', 'hashsed', { optional => settings });
sub validate {
    # Should return truthiness of plaintext against hash provided.
    # Wil try the following in order:
    # Scan hash for scheme used...
    # Else check options passed to method, try to use those
    # If no options passed, try default config

    my ($self, $plain, $hashed, $options) = @_;
}


# password->generate('plaintext', { optional => settings });
sub generate {
    # Default to returning the as_rfc2307() representation
    # Or set a flag in the $args to return object.
    my ($self, $passphrase, $options) = @_;

    my $config = _get_config($options);

    my $ppr = use_module("Authen::Passphrase::$config->{scheme}")->new(
         %{$config->{settings}}, (passphrase => $passphrase)
    );

    if ($config->{return_object}) {
        return $ppr;
    }

    return $ppr->as_rfc2307();
}



# Default settings for all schemes, lists ALL settings. Priority is:
# Arguments to method >> Config.yml >> defaults set here
sub _get_config {
    my ($args) = @_;

    my $scheme = $args->{scheme} || plugin_setting->{scheme} || 'BlowfishCrypt';
    my $return_object = $args->{return_object} || 0;

    delete @$args{'scheme', 'return_object'};

    # TODO: Expand this list.
    my $default_settings = {
        BlowfishCrypt => {
            cost        => 4,
            salt_random => 1
        },
        SaltedHash => {
            algorithm => 'SHA-256',
        },
    };

    my $config_settings = plugin_setting->{$scheme} || {};
    my $passed_settings = $args || {};

    return {
        scheme        => $scheme,
        return_object => $return_object,
        settings      => {
            %{$default_settings->{$scheme}}, # Default settings...
            %{$config_settings},             # Overridden by config.yml...
            %{$passed_settings},             # Overridden by arguments.
        }
    };

}



register_plugin;


1;

