package password;
use Dancer ':syntax';

use Dancer::Logger qw(error);

use MIME::Base64 qw(encode_base64 decode_base64);
use Data::Dumper;
use Digest;
use Dancer::Plugin::Passphrase;
use Encode qw(encode_utf8);

our $VERSION = '0.1';

my $secret = "hello";


get '/' => sub {

    my $output;
    for (qw(MD2 MD4 MD5 SHA-1 SHA-224 SHA-256 SHA-384 SHA-512 BCRYPT Whirlpool)) {

        my $encoded = $secret;
        if ($_ ~~ [qw(MD2 MD4 MD5 bcrypt BCRYPT)]) {
            $encoded = encode_utf8($encoded);
        } else {
            $encoded = $secret;
        }

        my $random_salt  = passphrase($encoded)->generate_hash({scheme => $_, return_object => 1});
        my $defined_salt = passphrase($encoded)->generate_hash({scheme => $_, salt => 'TheSalt', return_object => 1});
        my $empty_salt   = passphrase($encoded)->generate_hash({scheme => $_, salt => '', return_object => 1});

        $output->{'Random'}->{$_} = {
            rfc2307      => $random_salt->rfc2307,
            invalid_pass => passphrase('WRONG')->matches($random_salt->rfc2307),
            valid_pass   => passphrase($encoded)->matches($random_salt->rfc2307),
        };

        $output->{'None'}->{$_} = {
            rfc2307      => $empty_salt->rfc2307,
            invalid_pass => passphrase('WRONG')->matches($empty_salt->rfc2307),
            valid_pass   => passphrase($encoded)->matches($empty_salt->rfc2307),
        };

        $output->{'Defined'}->{$_} = {
            rfc2307      => $defined_salt->rfc2307,
            invalid_pass => passphrase('WRONG')->matches($defined_salt->rfc2307),
            valid_pass   => passphrase($encoded)->matches($defined_salt->rfc2307),
        };

    }

    die Dumper($output);

};



true;
