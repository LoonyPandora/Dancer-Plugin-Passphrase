package password;
use Dancer ':syntax';

use Dancer::Plugin::Passphrase;
use Dancer::Plugin::Database;

use Data::Dumper;

our $VERSION = '0.1';


my $password = 'My Password';


get '/' => sub {

    my $tests = {};

    $tests->{ssha}   = generate_test('SaltedDigest');
    $tests->{bcrypt} = generate_test('BlowfishCrypt');

    template 'index', {
        tests => $tests,
    };
};


sub generate_test {
    my ($scheme) = @_;
    return undef unless $scheme;

    my $hash = password->generate_hash($password, { scheme => $scheme });

    return {
        plaintext  => $password,
        hash       => $hash,
        is_valid   => password->is_valid($password, $hash),
        not_valid  => password->is_valid('wrongun', $hash),
#        salt       => password->extract_salt($hash),
    }

}



true;
