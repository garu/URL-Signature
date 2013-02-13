package URL::Signature;

use warnings;
use strict;

use URI             ();
use URI::QueryParam ();
use MIME::Base64    ();
use Digest::HMAC    ();
use Carp            ();
use Class::Load     ();
use Params::Util    qw( _STRING _POSINT _NONNEGINT _CLASS );

our $VERSION = '0.01';


sub new {
    my ($class, %attrs) = @_;
    Carp::croak('you must specify a secret key!')
        unless exists $attrs{'key'} and defined _STRING($attrs{'key'});

    # Digest::SHA defaults to SHA-1
    $attrs{'digest'} ||= 'Digest::SHA';
    Carp::croak('digest must be a valid Perl class')
        unless defined _CLASS($attrs{'digest'})
           and Class::Load::load_class($attrs{'digest'});

    $attrs{'length'} ||= 28;
    Carp::croak('length should be a positive integer')
        unless defined _POSINT($attrs{'length'});

    $attrs{'format'} ||= 'path';
    Carp::croak(q[format should be either 'path' or 'query'])
        unless defined _STRING($attrs{'format'})
           and ($attrs{'format'} eq 'path' or $attrs{'format'} eq 'query');

    if ($attrs{'format'} eq 'path') {
        $attrs{'as'} = 1 unless exists $attrs{'as'};
        Carp::croak( q[in 'path' format, 'as' needs to be a non-negative integer])
            unless defined _NONNEGINT($attrs{'as'});
    }
    else {
        $attrs{'as'} ||= 'k';
        Carp::croak(q[in 'query' format, 'as' needs to be a valid string])
            unless defined _STRING($attrs{'as'});
    }

    $attrs{'hmac'} = Digest::HMAC->new( $attrs{'key'}, $attrs{'digest'} );

    return bless \%attrs, $class;
}

sub validate {
    my ($self, $path) = @_;
    my $uri = URI->new( $path );
    my $splitter = '_split_' . $self->{'format'};

    my ($code, $new_uri) = $self->$splitter( $uri );
    return unless $code and $uri;

    return if $code ne $self->code_for_uri( $new_uri );

    return $new_uri;
}

sub _split_path {          ## no critic qw(ProhibitUnusedPrivateSubroutines)
    my ($self, $uri) = @_;
    my @segments = $uri->path_segments;
    return if scalar @segments <= $self->{'as'};

    my $code = splice @segments, $self->{'as'}, 1;
    $uri->path_segments( @segments );

    return ($code, $uri);
}

sub _split_query {          ## no critic qw(ProhibitUnusedPrivateSubroutines)
    my ($self, $uri) = @_;
    my $code = $uri->query_param_delete( $self->{as} );
    return ($code, $uri);
}

sub code_for_uri {
    my ($self, $uri) = @_;

    # ensure query parameters are sorted before encoding.
    my %params = $uri->query_form;
    $uri->query_form( map { $_ => $params{$_} } sort keys %params );

    my $code = MIME::Base64::encode_base64url(
        $self->{hmac}->reset->add( $uri->as_string )->digest
    );

    # truncate the digest, if necessary
    $code = substr $code, 0, $self->{'length'};
    return $code;
}

sub encrypt {
    my ($self, $path) = @_;
    my $uri = URI->new( $path );
    my $code = $self->code_for_uri( $uri );

    my $appender = '_append_' . $self->{'format'};
    return $self->$appender( $uri, $code );
}

sub _append_path {          ## no critic qw(ProhibitUnusedPrivateSubroutines)
    my ($self, $uri, $code) = @_;
    my @segments = $uri->path_segments;
    return if scalar @segments <= $self->{'as'};
    splice @segments, $self->{'as'}, 0, $code;
    $uri->path_segments(@segments);
    return $uri;
}

sub _append_query {         ## no critic qw(ProhibitUnusedPrivateSubroutines)
    my ($self, $uri, $code) = @_;
    my $varname = $self->{as};
    my $code_check = $uri->query_param_delete($varname);
    Carp::croak("variable '$varname' (reserved for auth code) found in path")
        if $code_check;

    $uri->query_param_append( $varname => $code );
    return $uri;
}


42;
__END__
=head1 NAME

URL::Signature - Sign URLs to tamper-proof them


=head1 SYNOPSIS

  use URL::Signature;
  my $obj = URL::Signature->new( key => 'My secret key' );

  # code above is the same as:
  my $obj = URL::Signature->new(
          key    => 'My secret key',
          digest => 'Digest::SHA'
          length => 28,
          format => 'path',
          as     => 1, # where in the uri path should we
                       # look/place the signature.
  );

  # get a URI object with the HMAC signature attached to it
  my $url = $obj->encrypt( '/path/to/somewhere?data=stuff' );


  # if path is valid, get a URI object without the signature in it
  my $path = 'www.example.com/1b23094726520/some/path?data=value&other=extra';
  my $validated = $obj->validate($path);


Want to put your signatures in variables instead of the path? No problem! 

  my $obj = URL::Signature->new(
          key    => 'My secret key',
          format => 'query',
          as     => 'foo', # variable name for us to
                           # look/place the signature
  );

  my $path = 'www.example.com/some/path?data=value&foo=1b23094726520&other=extra';
  my $validated = $obj->validate($path);

  my $url = $obj->encrypt( '/path/to/somewhere?data=stuff' );


Check below for some examples on how to integrate the integrity check to
som L<popular Perl web frameworks/EXAMPLES>.
  
=head1 DESCRIPTION

This module is a simple wrapper around L<Digest::HMAC> and <URI>. It is
intended to make it simple to do integrity checks on URLs (and other URIs
as well).

=head2 URL Tampering?

Sometimes you want to provide dynamic resources in your server based on
path or query parameters. An image server, for instance, might want to
provide different sizes and effects for images like so:

  http://myserver/images/150x150/flipped/perl.png

A malicious user might take advantage of that to try and traverse through
options or even L<DoS|https://en.wikipedia.org/wiki/Denial-of-service_attack>
your application by forcing it to do tons of unnecessary processing and
filesystem operations.

One way to prevent this is to sign your URLs with HMAC and a secret key.
In this approach, you authenticate your URL and append the resulting code
to it. The above URL could look like this:

  http://myserver/images/041da974ac0390b7340/150x150/flipped/perl.png

  or

  http://myserver/images/150x150/flipped/perl.png?k=041da974ac0390b7340

This way, whenever your server receives a request, it can check the URL
to see if the provided code matches the rest of the path. If a malicious
user tries to tamper with the URL, the provided code will be a mismatch
to the tampered path and you'll be able to catch it early on.

It is worth noticing that, when in C<'query'> mode, the
B<key order is not important for validation>. That means the following
URIs are all considered valid (for the same given secret key):

    foo/bar?a=1&b=2&k=SOME_KEY
    foo/bar?a=1&k=SOME_KEY&b=2
    foo/bar?b=2&k=SOME_KEY&a=1
    foo/bar?b=2&a=1&k=SOME_KEY
    foo/bar?k=SOME_KEY&a=1&b=2
    foo/var?k=SOME_KEY&b=2&a=1


=head1 METHODS

=head2 new( %attributes )

Instatiates a new object. You can set the following properties:

=over 4

=item * B<key> - (B<REQUIRED>) A string containing the secret key
used to generate and validate the URIs. As a security feature, this
attribute contains no default value and is mandatory. Typically,
your application will fetch the secret key from a configuration
file of some sort.

=item * B<length> - The size of the resulting code string to be
appended in your URIs. This needs to be a positive integer, and
defaults to B<28>. Note that, the smaller the string, the easier
it is for a malicious user to brute-force it.

=item * B<format> - Can be set to either 'I<path>' or 'I<query>'.
When set to 'path', the authentication code will be injected into
(and extracted from) one of the URI's segment. When set to 'query',
it will be injected/extracted as a query parameter. Default is B<path>.

=item * B<as> - When the format is 'I<path>', this option will specify
the segment's position in which to inject/extract the authentication code.
If the format is set to 'path', this option defaults to B<1>. When the
format is 'I<query>', this option specifies the query parameter's name,
and defaults to 'B<k>'.

=item * B<digest> - The name of the module handling the message digest
algorithm to be used. This is typically one of the C<Digest::> modules,
and it must comply with the 'Digest' interface on CPAN. Defaults to
L<Digest::SHA>, which uses the SHA-1 algorithm by default.

=back

=head2 encrypt( $url_string )

Receives a string containing the URL to be encrypted. Returns a
L<URI> object with the original URL modified to contain the
authentication code.

=head2 validate( $url_string )

Receives a string containing the URL to be validated. Returns
false if the URL's auth code is not a match, otherwise returns
an L<URI> object containing the original URL minus the
authentication code.

=head2 code_for_uri( $uri_object )

This is a convenience method that you probably won't need. It
receives an URI object and returns a string containing the
authentication code necessary for that object.


=head1 EXAMPLES

=head2 Dancer Integration

    use Dancer;
    use URL::Signature;

    my $validator = URL::Signature->new( key => 'my-secret-key' );

    hook 'before' => sub {
        my $uri = $validator->validate( request->uri )
                    or return send_error('forbidden', 403);

        # The following line is required only in 'path' mode, as
        # we need to remove the actual auth code from the request
        # path, otherwise Dancer won't find the real route.
        request->path( $uri->path );
    };

    get '/some/route' => sub {
            return 'Hi there, Miss Integrity!';
    };

    start;



=head2 Plack Integration

    package Plack::App::MyApp;
    use parent qw(Plack::Component);
    use URL::Signature;
    my $validator = URL::Signature->new( key => 'my-secret-key' );

    sub call {
      my ($self, $env) = @_;
      return [403, ['Content-Type' => 'text/plain', 'Content-Length' => 9], ['forbidden']]
          unless $validator->validate( $env->{REQUEST_URI} );

      return [200, ['Content-Type' => 'text/plain', 'Content-Lengh' => 10], ['Validated!']];
    }
    
    package main;
    
    my $app = Plack::App::MyApp->new->to_app;


=head1 DIAGNOSTICS

Messages from the constructor:

=over 4

=item C<< digest must be a valid Perl class >>

When setting the 'digest' attribute, it must be a string containing
a valid module name, like C<'Digest::SHA'> or C<'Digest::MD5'>.

=item C<< length should be a positive integer >>

When setting the 'length' attribute, make sure its greater than zero.

=item C<< format should be either 'path' or 'query' >>

Self-explanatory :)

=item C<< in 'path' format, 'as' needs to be a non-negative integer >>

The 'path' mode means the auth code will be inserted as one of the
URI segments. This means that, if you have a URI like:

   foo/bar/baz

Then if 'as' is 0, it will change to:

   CODE/foo/bar/baz

With 'as' set to 1 (the default for path mode), it changes to:

   foo/CODE/bar/baz

And so on. As such, the value for 'as' should be 0 or greater.

=item C<< in 'query' format, 'as' needs to be a valid string >>

The 'query' mode means the auth code will be inserted as one of the
URI variables (query parameters). This means that, if you have a URI like:

   foo/bar/baz

Then if 'as' is set to 'k' (the default for query mode), it will change to:

   foo/bar/baz?k=CODE

As such, the value for 'as' should be a valid string.

=back

Messages from C<encrypt()>:

=over 4

=item C<< variable '%s' (reserved for auth code) found in path >>

When in query mode, the object will throw this exception when it
tries to append the authentication code into the given URI, but
finds that a variable with the same name already exists (the
'as' parameter in the constructor).

=back


=head1 CONFIGURATION AND ENVIRONMENT

URL::Signature requires no configuration files or environment variables.


=head1 BUGS AND LIMITATIONS

Please report any bugs or feature requests to
C<bug-url-encrypt@rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org>.


=head1 AUTHOR

Breno G. de Oliveira  C<< <garu@cpan.org> >>


=head1 LICENCE AND COPYRIGHT

Copyright (c) 2013, Breno G. de Oliveira C<< <garu@cpan.org> >>. All rights reserved.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.


=head1 DISCLAIMER OF WARRANTY

BECAUSE THIS SOFTWARE IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
FOR THE SOFTWARE, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN
OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
PROVIDE THE SOFTWARE "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE SOFTWARE IS WITH
YOU. SHOULD THE SOFTWARE PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL
NECESSARY SERVICING, REPAIR, OR CORRECTION.

IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
REDISTRIBUTE THE SOFTWARE AS PERMITTED BY THE ABOVE LICENCE, BE
LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL,
OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE
THE SOFTWARE (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING
RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A
FAILURE OF THE SOFTWARE TO OPERATE WITH ANY OTHER SOFTWARE), EVEN IF
SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF
SUCH DAMAGES.

=cut
