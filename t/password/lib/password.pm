package password;
use Dancer ':syntax';

use Authen::Passphrase;
use Authen::Passphrase::SaltedDigest;


use Dancer::Plugin::Passphrase;
use Dancer::Logger qw/error/;

use MIME::Base64 2.21 qw(encode_base64 decode_base64);

use Data::Dumper;

our $VERSION = '0.1';


my $passphrase = 'My Password';


get '/' => sub {

    my $tests = {};



#    die Dumper(passphrase($passphrase)->matches({
        #hash_hex => '14ddb8585ddfc6c4670b9c18aed1fe8b',
#        hash_base64 => 'FN24WF3fxsRnC5wYrtH+iw==',
#        scheme   => 'MD5',
#    }));


#    my %pass = passphrase($passphrase)->generate_hash({
#        package     => 'SaltedDigest',
#        algorithm   => 'SHA-1',
#        salt_random => 20,
#    });

#    die Dumper(\%pass);

    my $pass = passphrase->matches;
    die Dumper($pass);


#     die Dumper(passphrase($passphrase)->matches('{CRYPT}$2a$03$8M6BSqKBglqLfE6vg6IvvOyMw2fEy6dlSmcKz19Y4GKDvJO.vPWZ.'));






    $tests->{raw_md5} = {
        plaintext    => $passphrase,
        hash         => '14ddb8585ddfc6c4670b9c18aed1fe8b',
    };


    template 'index', {
        tests => $tests,
    };
};





true;
