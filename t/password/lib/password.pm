package password;
use Dancer ':syntax';


use Dancer::Plugin::Passphrase;
use Dancer::Logger qw/error/;

use MIME::Base64 2.21 qw(encode_base64 decode_base64);

use Data::Dumper;

our $VERSION = '0.1';

my $passphrase = 'ThePassword';
my $salt       = 'TheSalt';

# only need to test functionality of this module
# Authen::Passphrase comes with a lot of tests, and covers
# generating hashes just fine.



=cut

- Generate bcrypt hash from password
- Match generated pass to original password
    - Test that correct password works
    - incorrect password fails

- Generate SaltedHash style hash by passing custom settings
- Match against password without specifying scheme
    - Test that correct password works
    - incorrect password fails

- Match password against plain hash with no scheme
    - With salt_hex
    - salt_base64
    - hash_hex
    - hash_base64

- Generate random password
- Generate hash in list context, check values




want to just pass package

=cut


get '/' => sub {

    my $tests = {};



    my $pass = passphrase($passphrase)->generate_hash({
        package     => 'SaltedDigest',
#        algorithm   => 'SHA-1',
#        salt        => $salt,
#        salt_before => 1,
#        salt_join   => '',
    });



    die Dumper($pass);

#    die Dumper(passphrase($passphrase)->matches({
        #hash_hex => '14ddb8585ddfc6c4670b9c18aed1fe8b',
#        hash_base64 => 'FN24WF3fxsRnC5wYrtH+iw==',
#        algorithm   => 'MD5',
#        package => 'SaltedDigest',
#    }));


#    die Dumper(\%pass);

#     die Dumper(passphrase($passphrase)->matches('{CRYPT}$2a$03$8M6BSqKBglqLfE6vg6IvvOyMw2fEy6dlSmcKz19Y4GKDvJO.vPWZ.'));

#    my $pass = passphrase->matches;
#    die Dumper($pass);


    $tests->{raw_md5} = {
        plaintext    => $passphrase,
        hash         => '14ddb8585ddfc6c4670b9c18aed1fe8b',
    };


    template 'index', {
        tests => $tests,
    };
};





true;
