package password;
use Dancer ':syntax';

use Authen::Passphrase;
use Authen::Passphrase::SaltedDigest;


use Dancer::Plugin::Passphrase;
use Dancer::Logger qw/error/;

use MIME::Base64 2.21 qw(encode_base64 decode_base64);

use Data::Dumper;

our $VERSION = '0.1';


my $password = 'My Password';


get '/' => sub {

    my $tests = {};




#    die Dumper(password($password)->matches({hash_hex => '14ddb8585ddfc6c4670b9c18aed1fe8b', scheme => 'MD5' }));


 #   die Dumper(password($password)->generate_hash());

    die Dumper(password($password)->generate_hash({
        package    => 'SaltedDigest',
        algorithm  => 'SHA-1',
        salt_random => 20,
    }));


#    die Dumper(password($password)->generate_hash());


#     die Dumper(password($password)->matches('{CRYPT}$2a$03$8M6BSqKBglqLfE6vg6IvvOyMw2fEy6dlSmcKz19Y4GKDvJO.vPWZ.'));






    $tests->{raw_md5} = {
        plaintext    => $password,
        hash         => '14ddb8585ddfc6c4670b9c18aed1fe8b',
    };


    template 'index', {
        tests => $tests,
    };
};





true;
