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


#    my $md5 = '14ddb8585ddfc6c4670b9c18aed1fe8b';

#    die password->is_valid('My Passworda', $md5, { scheme => 'SaltedDigest', algorithm => 'MD5', encoding => 'hash_hex' });

    $tests->{raw_md5} = {
        plaintext    => $password,
        hash         => '14ddb8585ddfc6c4670b9c18aed1fe8b',
    };


    template 'index', {
        tests => $tests,
    };
};


sub generate_test {
    my ($scheme) = @_;
    return undef unless $scheme;

    my $hash = password->generate_hash($password, { scheme => $scheme });

    return {
        plaintext       => $password,
        hash            => $hash,
        is_valid        => password->is_valid($password, $hash),
        not_valid       => password->is_valid('wrongun', $hash),
        salt            => password->extract_salt($hash),
        algorithm       => password->extract_algorithm($hash),
        cost            => password->extract_cost($hash),
        extracted_hash  => password->extract_hash($hash),
}

}



true;
