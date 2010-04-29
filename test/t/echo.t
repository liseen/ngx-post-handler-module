# vi:filetype=perl

use lib 'lib';
use Test::Nginx::Echo;

plan tests => 1 * blocks();

$Test::Nginx::Echo::LogLevel = 'debug';

run_tests();

__DATA__
=== TEST 1: sanity
--- config
    location /parrot {
        post_handler parrot 12345;
    }
--- request
POST /parrot
000000001
--- response_body chomp
000000001000000001000000001000000001000000001
